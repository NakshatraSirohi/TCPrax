"""
TCP Connect Scan Engine

Implements multi-threaded TCP Connect scanning using standard
socket.connect_ex() semantics.

Responsibilities:
- Probe ports via OS-level TCP handshake behavior
- Delegate result interpretation to core/port_state.py
  (OPEN / CLOSED / FILTERED / OTHER / ERROR)
- Use an adaptive timeout that learns from live RTT observations
- Re-probe uncertain ports (FILTERED / OTHER) when retries are enabled
- Execute scans concurrently via ThreadPoolExecutor
"""

import socket
import time
from typing import List, Dict
from .timeout import AdaptiveTimeout
from .retry import probe_with_retries
from .scheduler import run_port_tasks
from .port_state import (CLOSED, FILTERED, OPEN, classify_connect_exception,
                         classify_connect_result)


def probe_connect_port(target_ip: str, dest_port: int, timeout: float) -> str:
    """
    Performs one TCP connect() probe against a single port.

    A fresh TCP socket is created for every call, so each call
    (initial attempt or retry) is an independent network probe.

    Parameters:
        target_ip: Resolved IPv4 address of the target
        dest_port: Destination TCP port
        timeout: Socket timeout in seconds (adaptive)

    Behavior:
        - Uses connect_ex() to avoid raising exceptions on failure
        - Classifies the errno result via core/port_state.py
        - Relies on kernel TCP stack (full 3-way handshake)

    Returns:
        Observed port state.
    """

    tcp_sock = None

    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(timeout)

        # connect_ex returns 0 on success, else errno-style error code
        result = tcp_sock.connect_ex((target_ip, dest_port))
        state = classify_connect_result(result)

    except Exception as exc:
        state = classify_connect_exception(exc)
    finally:
        if tcp_sock is not None:
            tcp_sock.close()

    return state


def scan_single_port(target_ip: str,
                     dest_port: int,
                     adaptive: AdaptiveTimeout,
                     retries: int = 0) -> Dict:
    """
    Performs a TCP connect() scan against a single port, re-probing
    uncertain results up to `retries` additional times.

    Each attempt reads the current adaptive timeout, times the probe, and
    feeds the outcome back to the shared estimator: a completed round trip
    (OPEN or CLOSED) is a valid RTT sample, while FILTERED (no answer
    before the timeout) is recorded as a timeout event. OTHER and ERROR
    results are neither, so they never distort the estimate.

    Parameters:
        target_ip: Resolved IPv4 address of the target
        dest_port: Destination TCP port
        adaptive: Shared adaptive timeout (RTT estimator + policy)
        retries: Additional attempts for FILTERED / OTHER results

    Returns:
        Dictionary containing:
            ip
            port
            scan_type
            state         (final state)
            observations  (state recorded for each attempt)
    """

    def probe() -> str:
        timeout = adaptive.timeout()
        start = time.perf_counter()
        state = probe_connect_port(target_ip, dest_port, timeout)
        elapsed = time.perf_counter() - start

        if state in (OPEN, CLOSED):
            adaptive.update(elapsed)
        elif state == FILTERED:
            adaptive.observe_timeout()
        return state

    state, observations = probe_with_retries(probe, retries)

    return {
        "ip": target_ip,
        "port": dest_port,
        "scan_type": "tcp_connect_scan",
        "state": state,
        "observations": observations
    }


def connect_scan(target_ip: str,
                 ports: set,
                 workers: int = 20,
                 retries: int = 0,
                 on_result=None,
                 should_cancel=None) -> List[Dict]:
    """
    Executes a multi-threaded TCP Connect scan over a set of ports.

    Parameters:
        target_ip: Resolved IPv4 address of the target
        ports: Set of destination ports
        workers: Maximum concurrent scanning threads (default 20)
        retries: Additional attempts for FILTERED / OTHER results
        on_result: Optional per-port result callback (progress streaming)
        should_cancel: Optional predicate for cooperative cancellation

    Workflow:
        1. Build a shared adaptive timeout (RTT estimator + policy).
        2. Dispatch scan_single_port() tasks over a bounded thread pool.
        3. Collect results and sort by port for deterministic output.

    Returns:
        List of result dictionaries sorted by port (partial if cancelled).
    """

    adaptive = AdaptiveTimeout()

    def task(port: int) -> Dict:
        return scan_single_port(target_ip, port, adaptive, retries)

    return run_port_tasks(ports, task, workers, on_result=on_result,
                          should_cancel=should_cancel)
