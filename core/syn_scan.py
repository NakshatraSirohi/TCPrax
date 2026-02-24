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

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


def resolve_src_ip() -> str:
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.connect(("8.8.8.8", 80))
        return temp_sock.getsockname()[0]
    finally:
        temp_sock.close()


def scan_single_syn_port(src_ip: str, target_ip: str, dest_port: int,
                         timeout: float) -> Dict:

    state = "FILTERED"

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
        raw_sock.settimeout(timeout)

        src_port = random.randint(SRC_PORT_START, SRC_PORT_END)

        packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

        raw_sock.sendto(packet, (target_ip, dest_port))

        start_time = time.perf_counter()

        while (time.perf_counter() - start_time) <= timeout:
            try:
                packet_recv, _ = raw_sock.recvfrom(BUFFER_SIZE)
            except socket.timeout:
                break

            if len(packet_recv) < 20:
                continue

            ip_header = unpack('!BBHHHBBH4s4s', packet_recv[:20])
            ihl = ip_header[0] & 0x0F
            ip_header_len = ihl * 4

            if len(packet_recv) < ip_header_len + 20:
                continue

            if ip_header[6] != socket.IPPROTO_TCP:
                continue

            recv_src_ip = socket.inet_ntoa(ip_header[8])
            recv_dest_ip = socket.inet_ntoa(ip_header[9])

            if recv_src_ip != target_ip or recv_dest_ip != src_ip:
                continue

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

    results.sort(key=lambda x: x["port"])
    return results
