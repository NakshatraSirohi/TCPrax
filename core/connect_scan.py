import socket
import errno
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .timeout_calculation import calculate_timeout


def scan_single_port(target_ip: str, dest_port: int, timeout: float) -> Dict:
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(timeout)

    state = "OTHER"

    try:
        result = tcp_sock.connect_ex((target_ip, dest_port))

        if result == 0:
            state = "OPEN"
        elif result == errno.ECONNREFUSED:
            state = "CLOSED"
        elif result == errno.ETIMEDOUT:
            state = "FILTERED"
        else:
            state = "OTHER"

    except socket.timeout:
        state = "FILTERED"
    except Exception:
        state = "ERROR"
    finally:
        tcp_sock.close()

    return {
        "ip": target_ip,
        "port": dest_port,
        "scan_type": "tcp_connect_scan",
        "state": state
    }


def connect_scan(target_ip: str, ports: set, workers: int = 20) -> List[Dict]:
    timeout = calculate_timeout("-sT", target_ip)
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_single_port, target_ip, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    # Keep output order consistent (sorted by port)
    results.sort(key=lambda x: x["port"])

    return results
