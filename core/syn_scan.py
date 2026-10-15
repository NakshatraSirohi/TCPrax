"""
TCP SYN (Half-Open) Scan Engine

Implements raw-socket TCP SYN scanning using manual packet crafting.

Responsibilities:
- Send handcrafted TCP SYN segments
- Capture raw TCP responses and match them to probes
  (validation/matching in core/parse_tcp_packet.py)
- Delegate classification to core/port_state.py
- Re-probe uncertain ports (FILTERED / OTHER) when retries are enabled
- Execute scanning concurrently

Performance notes:
- Each worker thread reuses a single raw socket for every port it
  handles (see WorkerRawSocket), rather than creating one raw socket per
  probe. Source ports come from a shared thread-safe allocator so
  concurrent probes never collide on a source port.

Behavioral Notes:
- Requires root privileges (raw sockets)
- Kernel-generated RST packets must be suppressed externally
- Does not complete TCP handshake (half-open semantics)

Limitations:
- IPv4 only
- No TCP option parsing
"""

import random
import socket
import threading
import time
from struct import unpack_from
from typing import Collection, Dict, List

from .create_syn_packet import create_syn_packet
from .parse_tcp_packet import matches_probe, parse_ipv4_tcp
from .port_state import (CLOSED, ERROR, FILTERED, OPEN, OTHER,
                         classify_syn_response)
from .retry import probe_with_retries
from .scheduler import run_port_tasks
from .source_port import SourcePortAllocator, SourcePortExhausted
from .timeout import AdaptiveTimeout

BUFFER_SIZE = 65535
SRC_PORT_START = 50000
SRC_PORT_END = 51000


def resolve_src_ip() -> str:
    """
    Determines the local source IPv4 address used for outbound routing.

    Uses a UDP socket "connect" trick to query kernel routing decision
    without transmitting actual packets.

    Returns:
        Local IPv4 address selected by OS routing table.
    """
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.connect(("8.8.8.8", 80))
        return temp_sock.getsockname()[0]
    finally:
        temp_sock.close()


def choose_src_port(exclude: Collection[int] = ()) -> int:
    """
    Picks a random source port from the scanner's source-port range.

    Used as a fallback when the shared allocator is exhausted, and by
    callers that do not supply an allocator. Ports in `exclude` are
    avoided when possible so a retry uses a different source port.
    """
    range_size = SRC_PORT_END - SRC_PORT_START + 1
    if len(exclude) >= range_size:
        exclude = ()

    while True:
        src_port = random.randint(SRC_PORT_START, SRC_PORT_END)
        if src_port not in exclude:
            return src_port


class WorkerRawSocket:
    """
    Per-thread raw socket, reused across the ports a worker handles.

    Each worker thread lazily creates its own raw socket on first use and
    reuses it for every subsequent probe, avoiding a socket() / close()
    syscall pair per port. Because each thread has its own socket, no
    mutable socket is shared between threads.

    A socket that fails is dropped via `discard()` so the next probe
    transparently creates a fresh one; a single failed probe never
    permanently disables the worker. `close_all()` reliably closes every
    socket created, and is called when the scan's thread pool shuts down.
    """

    def __init__(self):
        self._local = threading.local()
        self._sockets = []
        self._lock = threading.Lock()

    def get(self) -> socket.socket:
        """Returns this thread's raw socket, creating it if needed."""
        sock = getattr(self._local, "sock", None)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
            self._local.sock = sock
            with self._lock:
                self._sockets.append(sock)
        return sock

    def discard(self) -> None:
        """Closes and forgets this thread's socket after a failure."""
        sock = getattr(self._local, "sock", None)
        if sock is None:
            return
        self._local.sock = None
        with self._lock:
            if sock in self._sockets:
                self._sockets.remove(sock)
        try:
            sock.close()
        except OSError:
            pass

    def close_all(self) -> None:
        """Closes every socket created by any worker."""
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


def _send_and_receive(raw_sock: socket.socket, src_ip: str, target_ip: str,
                      dest_port: int, src_port: int, timeout: float) -> str:
    """
    Sends one SYN on `raw_sock` and classifies the first matching reply.

    Shared core used by both the one-off probe and the reused-socket
    path, so the craft/send/receive/classify logic is not duplicated.

    Workflow:
        1. Craft TCP SYN packet manually.
        2. Send via the given raw socket.
        3. Capture packets until the timeout deadline.
        4. Validate each packet and match it to this probe
           (addresses, ports, acknowledgment number).
        5. Classify the first matching reply.

    Classification:
        SYN-ACK            : OPEN
        RST                : CLOSED
        No valid reply     : FILTERED
        Other valid reply  : OTHER

    Raises:
        OSError on a socket-level failure (so the caller can recreate a
        reused socket).
    """

    packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

    # Initial sequence number of this SYN, used to validate the
    # acknowledgment number of replies.
    isn = unpack_from("!L", packet, 4)[0]

    raw_sock.sendto(packet, (target_ip, dest_port))

    deadline = time.perf_counter() + timeout

    # Raw sockets receive all inbound TCP segments delivered to this host,
    # not just responses to our probe (and a reused socket may still hold
    # unrelated packets from a previous probe window). Until the deadline
    # we capture packets, discard malformed ones, and keep only the
    # segment that matches this probe's addresses, ports and ISN.
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            break

        raw_sock.settimeout(remaining)
        try:
            packet_recv, _ = raw_sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            break

        segment = parse_ipv4_tcp(packet_recv)
        if segment is None:
            continue

        if not matches_probe(segment, target_ip, src_ip, dest_port, src_port,
                             isn):
            continue

        return classify_syn_response(segment.flags)

    return FILTERED


def probe_syn_port(src_ip: str, target_ip: str, dest_port: int, src_port: int,
                   timeout: float) -> str:
    """
    Performs one TCP SYN probe using a dedicated one-off raw socket.

    Creates a raw socket, sends a single SYN, classifies the reply, and
    closes the socket. Kept for direct/standalone use; the concurrent
    scan path reuses worker sockets instead (see scan_single_syn_port).

    Returns:
        Observed port state (ERROR on any local failure).
    """

    raw_sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
        return _send_and_receive(raw_sock, src_ip, target_ip, dest_port,
                                 src_port, timeout)
    except Exception:
        return ERROR
    finally:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


def scan_single_syn_port(src_ip: str,
                         target_ip: str,
                         dest_port: int,
                         adaptive: AdaptiveTimeout,
                         retries: int = 0,
                         pool: "WorkerRawSocket | None" = None,
                         allocator: "SourcePortAllocator | None" = None
                         ) -> Dict:
    """
    Performs a TCP SYN half-open scan against a single port, re-probing
    uncertain results up to `retries` additional times.

    Each attempt uses a distinct source port and a newly crafted SYN
    packet (new sequence number).

    Parameters:
        src_ip: Local IPv4 address
        target_ip: Destination IPv4 address
        dest_port: Target TCP port
        adaptive: Shared adaptive timeout (RTT estimator + policy)
        retries: Additional attempts for FILTERED / OTHER results
        pool: Optional per-worker raw socket to reuse. If None, each
              probe uses its own one-off socket.
        allocator: Optional shared source-port allocator. If None, a
              random source port is chosen per attempt.

    Returns:
        Dictionary containing:
            ip, port, scan_type, state (final), observations (per attempt)
    """

    used_src_ports = set()
    leased_ports = []

    def acquire_src_port() -> int:
        if allocator is not None:
            try:
                port = allocator.acquire(exclude=used_src_ports)
                leased_ports.append(port)
                return port
            except SourcePortExhausted:
                # Fall back to an unreserved port so the worker is never
                # stalled; the 4-tuple still differs by destination port.
                pass
        return choose_src_port(used_src_ports)

    def probe() -> str:
        src_port = acquire_src_port()
        used_src_ports.add(src_port)

        timeout = adaptive.timeout()
        start = time.perf_counter()
        if pool is None:
            state = probe_syn_port(src_ip, target_ip, dest_port, src_port,
                                   timeout)
        else:
            raw_sock = pool.get()
            try:
                state = _send_and_receive(raw_sock, src_ip, target_ip,
                                          dest_port, src_port, timeout)
            except OSError:
                # Socket-level failure: drop this worker's socket so the
                # next probe recreates it; record ERROR for this attempt.
                pool.discard()
                state = ERROR
            except Exception:
                state = ERROR

        elapsed = time.perf_counter() - start
        # Any matched reply (SYN-ACK, RST or an unusual flag combination)
        # is a real round trip; only a missing answer (FILTERED) is a
        # timeout event. ERROR is a local failure, never an RTT sample.
        if state in (OPEN, CLOSED, OTHER):
            adaptive.update(elapsed)
        elif state == FILTERED:
            adaptive.observe_timeout()
        return state

    try:
        state, observations = probe_with_retries(probe, retries)
    finally:
        if allocator is not None:
            for port in leased_ports:
                allocator.release(port)

    return {
        "ip": target_ip,
        "port": dest_port,
        "scan_type": "tcp_syn_scan",
        "state": state,
        "observations": observations
    }


def syn_scan(target_ip: str,
             ports: set,
             workers: int = 20,
             retries: int = 0,
             on_result=None,
             should_cancel=None) -> List[Dict]:
    """
    Executes multi-threaded TCP SYN scanning over a set of ports.

    Parameters:
        target_ip: Destination IPv4 address
        ports: Set of destination ports
        workers: Maximum concurrent raw-socket workers
        retries: Additional attempts for FILTERED / OTHER results
        on_result: Optional per-port result callback (progress streaming)
        should_cancel: Optional predicate for cooperative cancellation

    Workflow:
        1. Resolve local source IP.
        2. Build a shared adaptive timeout (RTT estimator + policy).
        3. Dispatch scan tasks over a bounded thread pool, reusing one
           raw socket per worker and a shared source-port allocator.
        4. Collect and sort results.

    Returns:
        List of scan result dictionaries sorted by port (partial if
        cancelled).
    """

    src_ip = resolve_src_ip()
    adaptive = AdaptiveTimeout()

    pool = WorkerRawSocket()
    allocator = SourcePortAllocator(SRC_PORT_START, SRC_PORT_END)

    def task(port: int) -> Dict:
        return scan_single_syn_port(src_ip,
                                    target_ip,
                                    port,
                                    adaptive,
                                    retries,
                                    pool=pool,
                                    allocator=allocator)

    try:
        return run_port_tasks(ports, task, workers, on_result=on_result,
                              should_cancel=should_cancel)
    finally:
        # Reliably close every worker socket when the scan ends.
        pool.close_all()
