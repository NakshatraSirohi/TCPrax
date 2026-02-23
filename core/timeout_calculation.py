import socket
import time
import random
from struct import unpack
from typing import Optional
from .create_syn_packet import create_syn_packet

# === Globals ===
CALIBRATION_PORTS = [80, 443, 22]
RTT_SAMPLES = []
TIMEOUT = None


# === TCP Connect Scan Timeout Calculation ===
def connect_scan_timeout(target_ip: str) -> None:
    for port in CALIBRATION_PORTS:
        connect_sock = None
        try:
            connect_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_sock.settimeout(2.0)
            response = connect_sock.connect_ex((target_ip, port))

            # connect_ex returns 0 if open else non-zero for error
            if (response == 0):
                connect_probe(target_ip, port)

        except (OSError, socket.timeout):
            # Safely ignore normal network failures (e.g., host down, port filtered)
            pass
        finally:
            if connect_sock:  # Safety check
                try:
                    connect_sock.close()
                except OSError:
                    pass


def connect_probe(target_ip: str, port: int) -> None:
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
def _wait_for_syn_response(raw_sock,
                           target_ip,
                           src_ip,
                           dest_port,
                           src_port,
                           timeout: float,
                           measure_rtt: bool = False,
                           start_rtt: Optional[float] = None):
    """
    Waits for matching SYN response packet.
    Returns:
        - True (if match, no RTT measurement)
        - float RTT (if measure_rtt=True)
        - False if no match
    """

    start_time = time.perf_counter()

    while (time.perf_counter() - start_time) < timeout:
        try:
            response, _ = raw_sock.recvfrom(65535)
        except socket.timeout:
            return False

        if len(response) < 20:
            continue

        ip_header = unpack('!BBHHHBBH4s4s', response[:20])
        ihl = ip_header[0] & 0x0F
        ip_len = ihl * 4

        if len(response) < (ip_len + 20):
            continue

        if ip_header[6] != socket.IPPROTO_TCP:
            continue

        recv_pkt_src_ip = socket.inet_ntoa(ip_header[8])
        recv_pkt_dest_ip = socket.inet_ntoa(ip_header[9])

        if ((recv_pkt_src_ip != target_ip) or (recv_pkt_dest_ip != src_ip)):
            continue

        recv_tcp_header = response[ip_len:ip_len + 20]
        unpack_tcph = unpack('!HHLLBBHHH', recv_tcp_header)

        if ((unpack_tcph[0] == dest_port) and (unpack_tcph[1] == src_port)):
            if measure_rtt and (start_rtt is not None):
                return time.perf_counter() - start_rtt
            return True

    return False


def is_port_open(src_ip: str, target_ip: str, dest_port: int) -> bool:
    raw_syn_sock = None
    try:
        src_port = random.randint(50000, 50500)

        packet = create_syn_packet(src_ip, target_ip, dest_port, src_port)

        raw_syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_TCP)
        raw_syn_sock.settimeout(2.0)

        raw_syn_sock.sendto(packet, (target_ip, dest_port))

        result = _wait_for_syn_response(raw_syn_sock,
                                        target_ip,
                                        src_ip,
                                        dest_port,
                                        src_port,
                                        timeout=2.0,
                                        measure_rtt=False)

        return bool(result)

    except (OSError, socket.timeout):
        # Catches raw socket permission errors or general network unreachability
        return False
    finally:
        if raw_syn_sock:
            try:
                raw_syn_sock.close()
            except OSError:
                pass


def syn_probe(src_ip: str, target_ip: str, dest_port: int) -> None:
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

            rtt = _wait_for_syn_response(raw_syn_sock,
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
    for dest_port in CALIBRATION_PORTS:
        if (is_port_open(src_ip, target_ip, dest_port)):
            syn_probe(src_ip, target_ip, dest_port)


# === Calculating Timeout ===
def calculate_timeout(method: str,
                      target_ip: str,
                      src_ip: str | None = None) -> float:
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
        TIMEOUT = median_rtt * 3
    else:
        TIMEOUT = 1.0

    TIMEOUT = max(0.5, min(TIMEOUT, 3.0))

    return TIMEOUT
