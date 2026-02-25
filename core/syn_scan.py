"""
TCP SYN (Half-Open) Scan Engine

Implements raw-socket TCP SYN scanning using manual packet crafting.

Responsibilities:
- Send handcrafted TCP SYN segments
- Capture and parse raw TCP responses
- Classify ports based on SYN-ACK / RST behavior
- Execute scanning concurrently

Behavioral Notes:
- Requires root privileges (raw sockets)
- Kernel-generated RST packets must be suppressed externally
- Does not complete TCP handshake (half-open semantics)

Limitations:
- IPv4 only
- No TCP option parsing
- No retransmission logic
"""

import socket
import random
import time
from struct import unpack
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .timeout_calculation import calculate_timeout
from .create_syn_packet import create_syn_packet

BUFFER_SIZE = 65535
SRC_PORT_START = 50000
SRC_PORT_END = 51000

# TCP flag bit masks
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


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


def scan_single_syn_port(src_ip: str, target_ip: str, dest_port: int,
                         timeout: float) -> Dict:
    """
    Performs a TCP SYN half-open scan against a single port.

    Parameters:
        src_ip: Local IPv4 address
        target_ip: Destination IPv4 address
        dest_port: Target TCP port
        timeout: Maximum wait time for response

    Workflow:
        1. Craft TCP SYN packet manually.
        2. Send via raw socket.
        3. Capture incoming packets.
        4. Match response by IP + port tuple.
        5. Classify based on TCP flags.

    Classification Logic:
        SYN-ACK  : OPEN
        RST      : CLOSED
        No reply : FILTERED

    Returns:
        Dictionary containing:
            ip
            port
            scan_type
            state
    """

    state = "FILTERED"

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
        raw_sock.settimeout(timeout)

        src_port = random.randint(SRC_PORT_START, SRC_PORT_END)

        packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

        raw_sock.sendto(packet, (target_ip, dest_port))

        start_time = time.perf_counter()

        # Raw sockets receive all inbound TCP segments delivered to this host,
        # not just responses to our probe. During the timeout window, we
        # capture packets indiscriminately and manually filter them using:
        #     (source IP, destination IP, source port, destination port)
        # to isolate the segment corresponding to our SYN probe.
        while (time.perf_counter() - start_time) <= timeout:
            try:
                packet_recv, _ = raw_sock.recvfrom(BUFFER_SIZE)
            except socket.timeout:
                break

            # Minimum IPv4 header length check
            if len(packet_recv) < 20:
                continue

            # Parse IPv4 header
            ip_header = unpack('!BBHHHBBH4s4s', packet_recv[:20])
            ihl = ip_header[0] & 0x0F
            ip_header_len = ihl * 4

            # Ensure full TCP header present
            if len(packet_recv) < ip_header_len + 20:
                continue

            # Filter only TCP packets
            if ip_header[6] != socket.IPPROTO_TCP:
                continue

            recv_src_ip = socket.inet_ntoa(ip_header[8])
            recv_dest_ip = socket.inet_ntoa(ip_header[9])

            # Match only responses for this probe
            if recv_src_ip != target_ip or recv_dest_ip != src_ip:
                continue

            # Parse TCP header
            tcp_header = packet_recv[ip_header_len:ip_header_len + 20]
            tcp_fields = unpack('!HHLLBBHHH', tcp_header)

            recv_src_port = tcp_fields[0]
            recv_dest_port = tcp_fields[1]
            tcp_flags = tcp_fields[5]

            if ((recv_src_port == dest_port) and (recv_dest_port == src_port)):

                if (tcp_flags & (SYN | ACK)) == (SYN | ACK):
                    state = "OPEN"
                    break
                elif (tcp_flags & RST) == RST:
                    state = "CLOSED"
                    break
                elif (tcp_flags & SYN) == SYN:
                    state = "OPEN (SYN-ONLY)"
                    break

    except Exception:
        state = "ERROR"

    finally:
        try:
            raw_sock.close()
        except Exception:
            pass

    return {
        "ip": target_ip,
        "port": dest_port,
        "scan_type": "tcp_syn_scan",
        "state": state
    }


def syn_scan(target_ip: str, ports: set, workers: int = 20) -> List[Dict]:
    """
    Executes multi-threaded TCP SYN scanning over a set of ports.

    Parameters:
        target_ip: Destination IPv4 address
        ports: Set of destination ports
        workers: Maximum concurrent raw-socket workers

    Workflow:
        1. Resolve local source IP.
        2. Compute adaptive timeout using RTT sampling.
        3. Dispatch scan tasks concurrently.
        4. Collect and sort results.

    Returns:
        List of scan result dictionaries sorted by port.
    """

    src_ip = resolve_src_ip()
    timeout = calculate_timeout("-sS", target_ip, src_ip)

    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_single_syn_port, src_ip, target_ip, port,
                            timeout) for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    # Deterministic output ordering
    results.sort(key=lambda x: x["port"])
    return results
