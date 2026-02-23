import socket
import random
import time
from struct import unpack
from typing import List, Dict
from .timeout_calculation import calculate_timeout
from .create_syn_packet import create_syn_packet

BUFFER_SIZE = 65535

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


def resolve_src_ip() -> str:
    temp_sock = None
    try:
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))
        return temp_sock.getsockname()[0]
    except OSError:
        raise RuntimeError("Unable to determine source IP.")
    finally:
        if temp_sock:
            temp_sock.close()


def syn_scan(target_ip: str, ports: set) -> List[Dict]:
    src_ip = resolve_src_ip()
    timeout = calculate_timeout("-sS", target_ip, src_ip)
    results = []

    try:
        raw_syn_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                       socket.IPPROTO_TCP)
    except OSError as e:
        raise RuntimeError("Raw socket creation failed. Run as root.") from e

    raw_syn_socket.settimeout(timeout)

    for sent_dest_port in ports:
        sent_src_port = random.randint(50000, 50500)

        packet_sent = create_syn_packet(src_ip, target_ip, sent_dest_port,
                                        sent_src_port)

        raw_syn_socket.sendto(packet_sent, (target_ip, sent_dest_port))

        state = "FILTERED"
        start_time = time.perf_counter()
        while (time.perf_counter() - start_time) <= timeout:
            try:
                packet_recv, _ = raw_syn_socket.recvfrom(BUFFER_SIZE)

                if len(packet_recv) < 20:
                    continue

                ip_header = unpack('!BBHHHBBH4s4s', packet_recv[:20])
                ihl = ip_header[0] & 0x0F
                ip_header_len = ihl * 4

                if len(packet_recv) < ip_header_len + 14:
                    continue

                if ip_header[6] != socket.IPPROTO_TCP:
                    continue

                recv_src_ip = socket.inet_ntoa(ip_header[8])
                recv_dest_ip = socket.inet_ntoa(ip_header[9])

                if ((recv_src_ip != target_ip) or (recv_dest_ip != src_ip)):
                    continue

                tcp_header = packet_recv[ip_header_len:ip_header_len + 20]
                tcp_fields = unpack('!HHLLBBHHH', tcp_header)

                recv_src_port = tcp_fields[0]
                recv_dest_port = tcp_fields[1]
                tcp_flags = tcp_fields[5]

                if recv_src_port == sent_dest_port and \
                   recv_dest_port == sent_src_port:

                    if (tcp_flags & (SYN | ACK)) == (SYN | ACK):
                        state = "OPEN"
                        break

                    elif (tcp_flags & RST) == RST:
                        state = "CLOSED"
                        break

                    elif (tcp_flags & SYN) == SYN:
                        state = "OPEN (SYN-ONLY)"
                        break

            except socket.timeout:
                break

        results.append({
            "ip": target_ip,
            "port": sent_dest_port,
            "scan_type": "tcp_syn_scan",
            "state": state
        })

        time.sleep(0.25)

    raw_syn_socket.close()

    return results
