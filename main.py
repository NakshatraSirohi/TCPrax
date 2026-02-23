import socket
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

    results = None
    target_ip = resolve_host(args.host)
    if (args.sT):
        results = connect_scan(target_ip, ports)
    elif (args.sS):
        results = syn_scan(target_ip, ports)

    if (args.sV):
        for result in results:
            if result["state"] == "OPEN":
                service_info = discover_service(target_ip, result["port"])
                result["service"] = service_info

    for result in results:
        line = f"{result['port']:5d}/tcp  {result['state']}"
        if args.sV and "service" in result:
            line += f"\n{result['service']}"
        print(line + "\n")


if __name__ == "__main__":
    main()
