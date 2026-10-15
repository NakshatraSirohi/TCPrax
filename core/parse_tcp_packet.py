"""
Raw TCP Response Parsing Module

Provides utilities for:
- Structural validation of raw IPv4 + TCP packets
- Extraction of the TCP fields needed for port-state classification
- Matching a received segment to the SYN probe that caused it

Parsing and matching are separated from classification
(core/port_state.py): this module answers "is this a well-formed reply
to my probe?", while port_state answers "what does the reply mean?".

Limitations:
- IPv4 only
- TCP options are skipped, not parsed
- TCP checksums are not verified (loopback traffic carries partial
  checksums, and the kernel/NIC validate checksums for real links)
"""

from dataclasses import dataclass
from struct import unpack_from
import socket

# TCP flag bit masks
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

IPV4_MIN_HEADER_LEN = 20
TCP_MIN_HEADER_LEN = 20


@dataclass(frozen=True)
class TCPSegment:
    """TCP fields of a received IPv4 packet relevant to scanning."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int


def parse_ipv4_tcp(packet: bytes) -> TCPSegment | None:
    """
    Validates a raw IPv4 packet and extracts its TCP header fields.

    Checks:
        - Packet long enough for a minimal IPv4 header
        - IP version is 4
        - IHL >= 5 (20 bytes) and header fits in the packet
        - IPv4 total length is consistent with the captured data
        - Not a non-initial fragment
        - Protocol is TCP
        - TCP data offset >= 5 (20 bytes) and header fits in the packet

    Returns:
        TCPSegment if the packet is a well-formed IPv4/TCP packet,
        otherwise None.
    """

    if len(packet) < IPV4_MIN_HEADER_LEN:
        return None

    version = packet[0] >> 4
    ip_header_len = (packet[0] & 0x0F) * 4

    if version != 4 or ip_header_len < IPV4_MIN_HEADER_LEN:
        return None

    (total_length, frag_field, protocol, src_addr,
     dst_addr) = unpack_from('!2xH2xHxB2x4s4s', packet)

    if not ip_header_len + TCP_MIN_HEADER_LEN <= total_length <= len(packet):
        return None

    # Fragment offset must be zero, otherwise no TCP header is present
    if frag_field & 0x1FFF:
        return None

    if protocol != socket.IPPROTO_TCP:
        return None

    (src_port, dst_port, seq, ack, offset_byte,
     flags) = unpack_from('!HHLLBB', packet, ip_header_len)

    tcp_header_len = (offset_byte >> 4) * 4
    if (tcp_header_len < TCP_MIN_HEADER_LEN
            or ip_header_len + tcp_header_len > total_length):
        return None

    return TCPSegment(src_ip=socket.inet_ntoa(src_addr),
                      dst_ip=socket.inet_ntoa(dst_addr),
                      src_port=src_port,
                      dst_port=dst_port,
                      seq=seq,
                      ack=ack,
                      flags=flags)


def matches_probe(segment: TCPSegment,
                  target_ip: str,
                  src_ip: str,
                  dest_port: int,
                  src_port: int,
                  isn: int | None = None) -> bool:
    """
    Determines whether a segment is a reply to a specific SYN probe.

    Matching:
        - Source IP / port must be the probed target IP / port
        - Destination IP / port must be the local probe IP / port
        - If the probe's initial sequence number (isn) is known and the
          segment carries ACK, the acknowledgment number must equal
          isn + 1. Per RFC 9293 (SYN-SENT processing), a segment with
          an unacceptable ACK is not a reply to this SYN and is ignored.

    Returns:
        True if the segment belongs to the probe.
    """

    if (segment.src_ip != target_ip or segment.dst_ip != src_ip
            or segment.src_port != dest_port or segment.dst_port != src_port):
        return False

    if isn is not None and segment.flags & ACK:
        return segment.ack == (isn + 1) & 0xFFFFFFFF

    return True
