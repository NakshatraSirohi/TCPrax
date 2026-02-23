import socket
import errno
from typing import List, Dict
from .timeout_calculation import calculate_timeout


def connect_scan(target_ip: str, ports: set) -> List[Dict]:
    timeout = calculate_timeout("-sT", target_ip)
    results = []

    for dest_port in ports:
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

        results.append({
            "ip": target_ip,
            "port": dest_port,
            "scan_type": "tcp_connect_scan",
            "state": state
        })

    return results
