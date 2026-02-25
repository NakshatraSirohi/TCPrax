"""
TCPrax Entry Point

Responsibilities:
- Parse CLI arguments
- Resolve target hostname
- Validate scan mode selection
- Dispatch appropriate scan engine
- Optionally perform service detection
- Display scan summary and metrics

This module acts strictly as the orchestration and presentation layer.
All scanning logic resides in core modules.
"""

import socket
import time
from cli import parse_arguments, parse_ports
from core.connect_scan import connect_scan
from core.syn_scan import syn_scan
from service.banner import discover_service


def resolve_host(target: str) -> str:
    """
    Resolves hostname or IPv4 string to IPv4 address.

    Raises:
        ValueError if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Hostname could not be resolved.")


def main():
    """
    Primary execution flow for TCPrax.

    Workflow:
        1. Parse CLI arguments.
        2. Validate scan mode.
        3. Resolve target.
        4. Execute selected scan engine.
        5. Optionally perform service detection.
        6. Display structured results and performance metrics.
    """

    args = parse_arguments()
    ports = parse_ports(args.ports)

    # Ensure mutually exclusive scan modes
    if args.sT and args.sS:
        raise ValueError("Choose only one scan type.")

    if not args.sT and not args.sS:
        raise ValueError("Specify a scan type (-sT or -sS).")

    # ---- Scan Summary ----
    target_ip = resolve_host(args.host)
    scan_type = "TCP Connect Scan (-sT)" if args.sT else "TCP SYN Scan (-sS)"
    total_ports = len(ports)

    print("=== TCPrax Scan Summary ===")
    print(f"Target          : {args.host}")
    print(f"Resolved IP     : {target_ip}")
    print(f"Scan Type       : {scan_type}")
    print(f"Threads Used    : {args.threads}")
    print(f"Total Ports     : {total_ports}")
    print(f"Service Detect  : {'Enabled' if args.sV else 'Disabled'}\n")

    # Start time of Scan
    start_time = time.perf_counter()

    # Dispatch selected scan engine
    if args.sT:
        results = connect_scan(target_ip, ports, workers=args.threads)
    else:
        results = syn_scan(target_ip, ports, workers=args.threads)

    # Optional service/version detection on open ports
    if args.sV:
        for result in results:
            if result["state"] == "OPEN":
                result["service"] = discover_service(target_ip, result["port"])

    # ---- Result Display ----
    for result in results:
        line = f"{result['port']:5d}/tcp  {result['state']}"
        if args.sV and "service" in result:
            line += f"\n{result['service']}\n"
        print(line)

    # End & Total time of Scan
    end_time = time.perf_counter()
    total_time = end_time - start_time

    # ---- Performance Metrics ----
    open_count = sum(1 for r in results if r["state"] == "OPEN")
    closed_count = sum(1 for r in results if r["state"] == "CLOSED")
    filtered_count = sum(1 for r in results if r["state"] == "FILTERED")
    scan_rate = total_ports / total_time if total_time > 0 else 0

    print("\n=== Scan Completed ===")
    print(f"Total Time      : {total_time:.3f} seconds")
    print(f"Scan Rate       : {scan_rate} ports/sec")
    print(f"Open Ports      : {open_count}")
    print(f"Closed Ports    : {closed_count}")
    print(f"Filtered Ports  : {filtered_count}")


if __name__ == "__main__":
    main()
