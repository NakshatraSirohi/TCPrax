import argparse


def parse_ports(port_string: str) -> list[int]:
    ports = set()

    parts = port_string.split(",")

    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            start = int(start.strip())
            end = int(end.strip())

            if start > end:
                raise ValueError("Invalid port range.")

            ports.update(range(start, end + 1))

        else:
            ports.add(int(part.strip()))

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "TCPrax - Custom TCP Scanner\n\n"
            "Example Usage:\n"
            "  sudo python3 main.py example.com -p 1-1000 -sS -sV -t 100\n"
            "  python3 main.py 192.168.1.1 -p 22,80,443 -sT -t 50"),
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("host", help="Target host (IP or domain)")

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Port(s) (e.g.: 80; 1-1000; 22,80,443; 1-20,40-75)")

    parser.add_argument("-sT", action="store_true", help="TCP Connect Scan")

    parser.add_argument("-sS",
                        action="store_true",
                        help="TCP SYN Scan (requires root)")

    parser.add_argument("-sV",
                        action="store_true",
                        help="Service/version detection")

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Number of concurrent threads (default: 20, recommended: 50-200)")

    # parser.add_argument("-t", "--threads", dest="t", ...)
    # to save the above thread parse value in "t" instead of "threads"
    # as by default parser.args has dest=long_option_name_without_dashes

    args = parser.parse_args()

    # Thread Safety Validation
    if args.threads < 1:
        parser.error("Thread count must be at least 1.")

    if args.threads > 300:
        parser.error(
            "Thread count too high. Risk of resource exhaustion (>300).")

    return args
