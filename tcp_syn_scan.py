import socket
import time
import sys
from struct import *
import random
"""
Firewall Rule to Drop RST Pkt from Kernel:
ENABLE: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 50000:50500 -j DROP
DISABLE: sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 50000:50500 -j DROP
"""

BUFFER_SIZE = 65535
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


# needed for calculation checksum
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


def create_syn_packet(source_ip, target_ip, dest_port, src_port):
    # tcp header fields
    tcp_src_port = src_port  # source port
    tcp_dest_port = dest_port  # destination port
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

    tcp_window = socket.htons(5840)  #	maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (
        tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_src_port, tcp_dest_port, tcp_seq,
                      tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                      tcp_check, tcp_urg_ptr)

    # pseudo header fields
    src_ip_address = socket.inet_aton(source_ip)
    dest_ip_address = socket.inet_aton(target_ip)
    placeholder = 0
    tcp_length = len(tcp_header)
    protocol = socket.IPPROTO_TCP

    pseudo_header = pack('!4s4sBBH', src_ip_address, dest_ip_address,
                         placeholder, protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header
    tcp_checksum = checksum(pseudo_header)

    # recalculating tcp header with checksum
    tcp_header_with_checksum = pack(
        '!HHLLBBH', tcp_src_port, tcp_dest_port, tcp_seq,
        tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + pack(
            '!H', tcp_checksum) + pack('!H', tcp_urg_ptr)

    return tcp_header_with_checksum


def calculate_timeout(target_ip, source_ip, send_sock, recv_sock):
    calibration_ports = [80]
    rtt_samples = []

    for dest_port in calibration_ports:
        for _ in range(5):
            src_port = random.randint(50000, 50500)
            packet = create_syn_packet(source_ip, target_ip, dest_port,
                                       src_port)

            start = time.perf_counter()
            send_sock.sendto(packet, (target_ip, dest_port))

            try:
                recv_sock.settimeout(1.5)
                while True:
                    data, _ = recv_sock.recvfrom(BUFFER_SIZE)

                    if len(data) < 20:
                        continue

                    ip_header = unpack('!BBHHHBBH4s4s', data[:20])
                    ihl = ip_header[0] & 0x0F
                    ip_len = ihl * 4
                    if len(data) < ip_len + 14:
                        continue

                    protocol = ip_header[6]
                    if protocol != socket.IPPROTO_TCP:
                        continue

                    src_ip_pkt = socket.inet_ntoa(ip_header[8])
                    dst_ip_pkt = socket.inet_ntoa(ip_header[9])

                    if (src_ip_pkt != target_ip) or (dst_ip_pkt != source_ip):
                        continue

                    tcp_header = data[ip_len:ip_len + 20]
                    tcph = unpack('!HHLLBBHHH', tcp_header)

                    if tcph[0] == dest_port and tcph[1] == src_port:
                        end = time.perf_counter()
                        rtt_samples.append(end - start)
                        break

            except socket.timeout:
                continue

    if not rtt_samples:
        return 1.0  # fallback

    avg_rtt = sum(rtt_samples) / len(rtt_samples)

    timeout = avg_rtt * 3
    timeout = max(0.5, min(timeout, 5.0))
    return timeout


def main():
    host = input("Enter host: ")
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))

    # to get outbound traffic ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    source_ip = s.getsockname()[0]
    s.close()

    # sending packet socket
    try:
        raw_send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                        socket.IPPROTO_TCP)
    except:
        print("Raw Send Socket creation failed.")
        sys.exit()

    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

    timeout = calculate_timeout(target_ip, source_ip, raw_send_socket,
                                raw_send_socket)
    print(
        f"Timeout: {timeout}\nSource IP: {source_ip}\nTarget IP: {target_ip}")
    raw_send_socket.settimeout(timeout)

    for dest_port in range(start_port, end_port + 1):
        print(f"Sending packet to port: {dest_port}")
        src_port = random.randint(50000, 50500)
        packet_sent = create_syn_packet(source_ip, target_ip, dest_port,
                                        src_port)
        raw_send_socket.sendto(packet_sent, (target_ip, dest_port))

        matched = False
        start_time = time.perf_counter()
        while (time.perf_counter() - start_time) < timeout:
            try:
                # giving full (Received) ip + tcp header -> [IP HEADER][TCP HEADER][DATA]
                # returns tuple of packet, address
                packet_recv, _ = raw_send_socket.recvfrom(BUFFER_SIZE)

                if len(packet_recv) < 20:
                    continue
                ip_header = unpack('!BBHHHBBH4s4s', packet_recv[:20])

                ihl = ip_header[0] & 0x0f
                ip_header_len = ihl * 4
                if len(packet_recv) < ip_header_len + 14:
                    continue

                protocol = ip_header[6]
                if (protocol != socket.IPPROTO_TCP):
                    continue

                src_ip = socket.inet_ntoa(ip_header[8])
                dst_ip = socket.inet_ntoa(ip_header[9])
                if (src_ip != target_ip or dst_ip != source_ip):
                    continue

                tcp_header = packet_recv[ip_header_len:ip_header_len + 20]
                tcp_fields = unpack('!HHLLBBHHH', tcp_header)
                tcp_src_port = tcp_fields[0]
                tcp_dest_port = tcp_fields[1]
                tcp_flags = tcp_fields[5]

                print("Got packet from:", src_ip, "ports:", tcp_src_port,
                      tcp_dest_port, "flags:", hex(tcp_flags))

                if (tcp_src_port == dest_port and tcp_dest_port == src_port):
                    if (tcp_flags & (SYN | ACK)) == (SYN | ACK):
                        # Port is OPEN (Received SYN + ACK)
                        print("STATUS: OPEN")
                        matched = True
                        break
                    elif (tcp_flags & RST) == RST:
                        # Port is CLOSED (Received RST or RST+ACK)
                        print("STATUS: CLOSED")
                        matched = True
                        break
                    elif (tcp_flags & SYN) == SYN:
                        # Rare case: Only SYN (Simultaneous open)
                        print("STATUS: OPEN (SYN-ONLY)")
                        matched = True
                        break

            except socket.timeout:
                break

        if not matched:
            print("FILTERED")

        time.sleep(0.5)
    print("\nScan Complete.")


if __name__ == "__main__":
    main()
