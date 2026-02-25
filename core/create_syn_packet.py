"""
Raw TCP SYN Packet Construction Module

Provides utilities for:
- IPv4 and port validation
- Internet checksum calculation
- Manual TCP SYN segment construction

This module crafts a minimal 20-byte TCP header (no options)
and computes the checksum using the IPv4 pseudo-header as
required by RFC 793.

Limitations:
- IPv4 only
- No TCP options (MSS, SACK, Window Scaling not included)
- Returns TCP header only (IP header must be handled by OS or caller)
"""

import socket
from struct import pack
import random


def validate_ipv4(ip: str, name: str) -> None:
    """
    Validates IPv4 address format using inet_aton().

    Raises:
        ValueError if invalid IPv4 string.
    """
    try:
        socket.inet_aton(ip)
    except OSError:
        raise ValueError(f"Invalid IPv4 {name} address: {ip}")


def validate_port(port: int, name: str) -> None:
    """
    Validates TCP port range and type.

    Ensures:
        - Integer type
        - Range 1–65535

    Raises:
        TypeError or ValueError on invalid input.
    """
    if not isinstance(port, int):
        raise TypeError(f"{name} must be an integer")
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be in range 1-65535")


def checksum(data: bytes) -> int:
    """
    Computes 16-bit one's complement checksum.

    Used for TCP checksum calculation over:
        pseudo-header + TCP header

    Behavior:
        - Pads odd-length data
        - Sums 16-bit words
        - Folds carry bits
        - Applies one's complement

    Returns:
        16-bit checksum value.
    """

    # If odd length, pad with one zero byte
    if len(data) % 2 != 0:
        data += b'\x00'

    s = 0

    # Process 16-bit words
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word

    # Fold carry bits into lower 16 bits
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)

    # One's complement
    s = ~s & 0xFFFF
    return s


def create_syn_packet(src_ip: str, target_ip: str, dest_port: int,
                      src_port: int) -> bytes:
    """
    Constructs a minimal TCP SYN segment.

    Parameters:
        src_ip: Source IPv4 address
        target_ip: Destination IPv4 address
        dest_port: Target TCP port
        src_port: Ephemeral source port

    Behavior:
        - Randomizes initial sequence number
        - Sets SYN flag only
        - Uses fixed 20-byte TCP header (no options)
        - Computes checksum using IPv4 pseudo-header

    Returns:
        Raw TCP header bytes (without IP header).
    """

    validate_ipv4(src_ip, "Source")
    validate_ipv4(target_ip, "Target")
    validate_port(src_port, "Source port")
    validate_port(dest_port, "Destination port")

    # TCP header core fields
    tcp_seq = random.randint(1, 4294967295)  # 32-bit ISN
    tcp_ack_seq = 0
    tcp_doff = 5  # Data offset: 5 * 4 = 20 bytes (no TCP options)

    # TCP flag configuration (SYN only)
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0

    tcp_window = 5840
    tcp_checksum = 0  # Placeholder before checksum calculation
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = ((tcp_fin) | (tcp_syn << 1) | (tcp_rst << 2) | (tcp_psh << 3) |
                 (tcp_ack << 4) | (tcp_urg << 5))

    # Pack initial TCP header (network byte order)
    tcp_header = pack('!HHLLBBHHH', src_port, dest_port, tcp_seq, tcp_ack_seq,
                      tcp_offset_res, tcp_flags, tcp_window, tcp_checksum,
                      tcp_urg_ptr)

    # IPv4 pseudo-header required for TCP checksum
    src_ip_addr = socket.inet_aton(src_ip)
    dest_ip_addr = socket.inet_aton(target_ip)
    placeholder = 0
    tcp_length = len(tcp_header)
    protocol = socket.IPPROTO_TCP

    pseudo_header = pack('!4s4sBBH', src_ip_addr, dest_ip_addr, placeholder,
                         protocol, tcp_length)

    pseudo_header = pseudo_header + tcp_header

    tcp_checksum = checksum(pseudo_header)

    # Repack TCP header including calculated checksum
    tcp_header_with_checksum = pack(
        '!HHLLBBH', src_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
        tcp_flags, tcp_window) + pack('!H', tcp_checksum) + pack(
            '!H', tcp_urg_ptr)

    return tcp_header_with_checksum
