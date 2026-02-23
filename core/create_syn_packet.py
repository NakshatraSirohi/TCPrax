import socket
from struct import pack
import random


def validate_ipv4(ip: str, name: str) -> None:
    try:
        socket.inet_aton(ip)
    except OSError:
        raise ValueError(f"Invalid IPv4 {name} address: {ip}")


def validate_port(port: int, name: str) -> None:
    if not isinstance(port, int):
        raise TypeError(f"{name} must be an integer")
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be in range 1 to 65535")


# checksum calculation of pseudo-header
def checksum(data: bytes) -> int:
    # If odd length, pad with one zero byte
    if len(data) % 2 != 0:
        data += b'\x00'

    s = 0
    # Process 2 bytes at a time
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word

    # Add carry bits
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)

    # One's complement
    s = ~s & 0xFFFF
    return s


def create_syn_packet(src_ip: str, target_ip: str, dest_port: int,
                      src_port: int) -> bytes:

    validate_ipv4(src_ip, "Source")
    validate_ipv4(target_ip, "Target")
    validate_port(src_port, "Source port")
    validate_port(dest_port, "Destination port")

    # tcp header fields
    tcp_seq = random.randint(1, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5  #4 bit field, size of tcp header, 5 * 4 = 20 bytes

    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0

    tcp_window = 5840
    tcp_checksum = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = ((tcp_fin) | (tcp_syn << 1) | (tcp_rst << 2) | (tcp_psh << 3) |
                 (tcp_ack << 4) | (tcp_urg << 5))

    # the ! in the pack format string means network order (endianess)
    tcp_header = pack('!HHLLBBHHH', src_port, dest_port, tcp_seq, tcp_ack_seq,
                      tcp_offset_res, tcp_flags, tcp_window, tcp_checksum,
                      tcp_urg_ptr)

    # pseudo header fields
    src_ip_addr = socket.inet_aton(src_ip)
    dest_ip_addr = socket.inet_aton(target_ip)
    placeholder = 0
    tcp_length = len(tcp_header)
    protocol = socket.IPPROTO_TCP

    pseudo_header = pack('!4s4sBBH', src_ip_addr, dest_ip_addr, placeholder,
                         protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header

    tcp_checksum = checksum(pseudo_header)

    # recalculating tcp header with checksum
    tcp_header_with_checksum = pack(
        '!HHLLBBH', src_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
        tcp_flags, tcp_window) + pack('!H', tcp_checksum) + pack(
            '!H', tcp_urg_ptr)

    return tcp_header_with_checksum
