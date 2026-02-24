import socket
import time
from cli import parse_arguments, parse_ports
from core.connect_scan import connect_scan
from core.syn_scan import syn_scan
from service.banner import discover_service


def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Hostname could not be resolved.")


def main():
    args = parse_arguments()
    ports = parse_ports(args.ports)

    if args.sT and args.sS:
        raise ValueError("Choose only one scan type.")

    if not args.sT and not args.sS:
        raise ValueError("Specify a scan type (-sT or -sS).")

    target_ip = resolve_host(args.host)

    scan_type = "TCP Connect Scan (-sT)" if args.sT else "TCP SYN Scan (-sS)"
    total_ports = len(ports)

    # START METRICS DISPLAY
    print("=== TCPrax Scan Summary ===")
    print(f"Target          : {args.host}")
    print(f"Resolved IP     : {target_ip}")
    print(f"Scan Type       : {scan_type}")
    print(f"Threads Used    : {args.threads}")
    print(f"Total Ports     : {total_ports}")
    print(f"Service Detect  : {'Enabled' if args.sV else 'Disabled'}\n")

    start_time = time.perf_counter()

    if args.sT:
        results = connect_scan(target_ip, ports, workers=args.threads)
    else:
        results = syn_scan(target_ip, ports, workers=args.threads)

    if args.sV:
        for result in results:
            if result["state"] == "OPEN":
                result["service"] = discover_service(target_ip, result["port"])

    for result in results:
        line = f"{result['port']:5d}/tcp  {result['state']}"
        if args.sV and "service" in result:
            line += f"\n{result['service']}\n"
        print(line)

    end_time = time.perf_counter()
    total_time = end_time - start_time

    # END METRICS
    open_count = sum(1 for r in results if r["state"] == "OPEN")
    closed_count = sum(1 for r in results if r["state"] == "CLOSED")
    filtered_count = sum(1 for r in results if r["state"] == "FILTERED")

    print("\n=== Scan Completed ===")
    print(f"Total Time      : {total_time:.2f} seconds")
    print(f"Scan Rate       : {total_ports / total_time:.2f} ports/sec")
    print(f"Open Ports      : {open_count}")
    print(f"Closed Ports    : {closed_count}")
    print(f"Filtered Ports  : {filtered_count}")


if __name__ == "__main__":
    main()
