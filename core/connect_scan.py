"""
TCP Connect Scan Engine

Implements multi-threaded TCP Connect scanning using standard
socket.connect_ex() semantics.

Responsibilities:
- Determine port state via OS-level TCP handshake behavior
- Classify responses into OPEN / CLOSED / FILTERED / OTHER / ERROR
- Use adaptive timeout derived from RTT calibration
- Execute scans concurrently via ThreadPoolExecutor
"""

import socket
import errno
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .timeout_calculation import calculate_timeout


def scan_single_port(target_ip: str, dest_port: int, timeout: float) -> Dict:
    """
    Performs a TCP connect() scan against a single port.

    Parameters:
        target_ip: Resolved IPv4 address of the target
        dest_port: Destination TCP port
        timeout: Socket timeout in seconds (adaptive)

    Behavior:
        - Uses connect_ex() to avoid raising exceptions on failure
        - Classifies result based on errno values
        - Relies on kernel TCP stack (full 3-way handshake)

    Returns:
        Dictionary containing:
            ip
            port
            scan_type
            state
    """

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(timeout)

    state = "OTHER"

    try:
        # connect_ex returns 0 on success, else errno-style error code
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
    """
    Executes a multi-threaded TCP Connect scan over a set of ports.

    Parameters:
        target_ip: Resolved IPv4 address of the target
        ports: Set of destination ports
        workers: Maximum concurrent scanning threads (default 20)

    Workflow:
        1. Compute adaptive timeout using RTT sampling.
        2. Dispatch scan_single_port() tasks concurrently.
        3. Collect results as futures complete.
        4. Sort results by port for deterministic output.

    Returns:
        List of result dictionaries sorted by port.
    """

    timeout = calculate_timeout("-sT", target_ip)
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_single_port, target_ip, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    # Ensure stable output ordering regardless of completion order
    results.sort(key=lambda x: x["port"])

    return results
