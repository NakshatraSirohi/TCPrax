"""
Adaptive Timeout Calibration Module

Implements RTT-based timeout estimation for both:
- TCP Connect Scan (-sT)
- TCP SYN Half-Open Scan (-sS)

Strategy:
1. Probe a small set of well-known ports.
2. Measure RTT from successful responses.
3. Compute median RTT.
4. Derive timeout as median * 3.
5. Clamp timeout within [0.5s, 3.0s].

Purpose:
- Avoid static timeouts.
- Adapt to local network latency.
- Improve scan accuracy across LAN/WAN environments.

Note:
- Uses global RTT_SAMPLES accumulator.
- Calibration only samples OPEN ports.
"""

import socket
import time
import random
from struct import unpack
from typing import Optional
from .create_syn_packet import create_syn_packet

CALIBRATION_PORTS = [80, 443, 22]  # Commonly open ports for RTT sampling
RTT_SAMPLES = []
TIMEOUT = None


# === TCP Connect Scan Timeout Calculation ===
def connect_scan_timeout(target_ip: str) -> None:
    """
    Performs RTT sampling using TCP connect_ex() semantics.

    For each calibration port:
        - Attempt connection.
        - If open, measure RTT via repeated probes.

    Only successful connections contribute to RTT_SAMPLES.
    """

    for port in CALIBRATION_PORTS:
        connect_sock = None
        try:
            connect_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_sock.settimeout(2.0)
            response = connect_sock.connect_ex((target_ip, port))

            # connect_ex returns 0 on success (port open)
            if (response == 0):
                connect_probe(target_ip, port)

        except (OSError, socket.timeout):
            # Ignore normal network failures (host down, filtered, etc.)
            pass
        finally:
            if connect_sock:
                try:
                    connect_sock.close()
                except OSError:
                    pass


def connect_probe(target_ip: str, port: int) -> None:
    """
    Collects RTT samples using full TCP handshake.

    Sends multiple connect attempts and records
    high-resolution timing for successful connections.
    """

    global RTT_SAMPLES

    for _ in range(5):
        connect_sock = None
        try:
            connect_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_sock.settimeout(2)

            start_rtt = time.perf_counter()
            result = connect_sock.connect_ex((target_ip, port))
            end_rtt = time.perf_counter()

            if (result == 0):
                rtt = end_rtt - start_rtt
                RTT_SAMPLES.append(rtt)

        except (OSError, socket.timeout):
            pass
        finally:
            if connect_sock:
                try:
                    connect_sock.close()
                except OSError:
                    pass


# === TCP Half-Open (SYN) Timeout Calculation ===
def wait_for_syn_response(raw_sock,
                          target_ip,
                          src_ip,
                          dest_port,
                          src_port,
                          timeout: float,
                          measure_rtt: bool = False,
                          start_rtt: Optional[float] = None):
    """
    Waits for a matching SYN response packet.

    Filters inbound TCP traffic using:
        - Source IP
        - Destination IP
        - Source port
        - Destination port

    Parameters:
        measure_rtt: If True, returns measured RTT instead of boolean.
        start_rtt: Timestamp recorded before SYN transmission.

    Returns:
        True        : Matching response received
        float (RTT) : If measure_rtt enabled
        False       : No matching packet within timeout
    """

    start_time = time.perf_counter()

    while (time.perf_counter() - start_time) < timeout:
        try:
            response, _ = raw_sock.recvfrom(65535)
        except socket.timeout:
            return False

        # Minimum IPv4 header length check
        if len(response) < 20:
            continue

        # Parse IPv4 header
        ip_header = unpack('!BBHHHBBH4s4s', response[:20])
        ihl = ip_header[0] & 0x0F
        ip_len = ihl * 4

        # Ensure full TCP header present
        if len(response) < (ip_len + 20):
            continue

        # Only process TCP packets
        if ip_header[6] != socket.IPPROTO_TCP:
            continue

        recv_pkt_src_ip = socket.inet_ntoa(ip_header[8])
        recv_pkt_dest_ip = socket.inet_ntoa(ip_header[9])

        # Match only responses for this probe
        if ((recv_pkt_src_ip != target_ip) or (recv_pkt_dest_ip != src_ip)):
            continue

        # Parse TCP header
        recv_tcp_header = response[ip_len:ip_len + 20]
        unpack_tcph = unpack('!HHLLBBHHH', recv_tcp_header)

        if ((unpack_tcph[0] == dest_port) and (unpack_tcph[1] == src_port)):
            if measure_rtt and (start_rtt is not None):
                return time.perf_counter() - start_rtt
            return True

    return False


def is_port_open(src_ip: str, target_ip: str, dest_port: int) -> bool:
    """
    Performs a single SYN probe to determine if a port is open.

    Returns:
        True  : Matching SYN-ACK observed
        False : No response / error
    """

    raw_syn_sock = None
    try:
        src_port = random.randint(50000, 50500)

        packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

        raw_syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_TCP)
        raw_syn_sock.settimeout(2.0)

        raw_syn_sock.sendto(packet, (target_ip, dest_port))

        result = wait_for_syn_response(raw_syn_sock,
                                       target_ip,
                                       src_ip,
                                       dest_port,
                                       src_port,
                                       timeout=2.0,
                                       measure_rtt=False)

        return bool(result)

    except (OSError, socket.timeout):
        # Includes raw socket permission errors and network failures
        return False
    finally:
        if raw_syn_sock:
            try:
                raw_syn_sock.close()
            except OSError:
                pass


def syn_probe(src_ip: str, target_ip: str, dest_port: int) -> None:
    """
    Collects RTT samples using SYN half-open semantics.

    Measures time between SYN transmission and matching SYN-ACK reception.
    """

    global RTT_SAMPLES

    for _ in range(5):
        raw_syn_sock = None
        try:
            src_port = random.randint(50000, 50500)

            packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

            raw_syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                         socket.IPPROTO_TCP)
            raw_syn_sock.settimeout(2.0)

            start_rtt = time.perf_counter()
            raw_syn_sock.sendto(packet, (target_ip, dest_port))

            rtt = wait_for_syn_response(raw_syn_sock,
                                        target_ip,
                                        src_ip,
                                        dest_port,
                                        src_port,
                                        timeout=2.0,
                                        measure_rtt=True,
                                        start_rtt=start_rtt)

            if isinstance(rtt, float):
                RTT_SAMPLES.append(rtt)

        except (OSError, socket.timeout):
            pass
        finally:
            if raw_syn_sock:
                try:
                    raw_syn_sock.close()
                except OSError:
                    pass


def syn_scan_timeout(src_ip: str, target_ip: str) -> None:
    """
    Performs RTT calibration using SYN probes.

    Only probes ports that appear open.
    """

    for dest_port in CALIBRATION_PORTS:
        if (is_port_open(src_ip, target_ip, dest_port)):
            syn_probe(src_ip, target_ip, dest_port)


# === Calculating Timeout ===
def calculate_timeout(method: str,
                      target_ip: str,
                      src_ip: str | None = None) -> float:
    """
    Computes adaptive timeout value for scan engines.

    Steps:
        1. Perform RTT calibration based on scan method.
        2. Compute median RTT.
        3. Multiply by 3 as safety margin.
        4. Clamp to range [0.5s, 3.0s].

    Returns:
        Final timeout value in seconds.
    """

    global RTT_SAMPLES, TIMEOUT

    RTT_SAMPLES = []

    if (method == "-sT"):
        connect_scan_timeout(target_ip)
    elif (method == "-sS"):
        syn_scan_timeout(src_ip, target_ip)
    else:
        raise ValueError("No valid method specified.")

    if RTT_SAMPLES:
        RTT_SAMPLES.sort()
        median_rtt = RTT_SAMPLES[len(RTT_SAMPLES) // 2]

        # Multiply median RTT to tolerate network jitter
        TIMEOUT = median_rtt * 3
    else:
        # Fallback if no samples collected
        TIMEOUT = 1.0

    # Bound timeout to prevent extreme values
    TIMEOUT = max(0.5, min(TIMEOUT, 3.0))

    return TIMEOUT
