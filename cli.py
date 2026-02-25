"""
CLI Parsing Module

Responsible for:
- Parsing command-line arguments
- Validating port input format
- Enforcing thread safety constraints

This module strictly handles user input parsing.
It does not execute any scanning logic.
"""

import argparse


def parse_ports(port_string: str) -> list[int]:
    """
    Parses user-supplied port specification string.

    Supported formats:
        - Single port: "80"
        - Range: "1-1000"
        - Comma-separated: "22,80,443"
        - Mixed: "1-20,40-75"

    Behavior:
        - Expands ranges inclusively.
        - Deduplicates ports using a set.
        - Validates port range (1–65535).
        - Returns sorted list of ports.

    Raises:
        ValueError for invalid ranges or out-of-bound ports.
    """

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

    # Validate port bounds
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def parse_arguments():
    """
    Defines and parses TCPrax command-line interface.

    Arguments:
        host         : Target hostname or IPv4 address
        -p/--ports   : Port specification string (required)
        -sT          : TCP Connect scan
        -sS          : TCP SYN scan (requires root)
        -sV          : Enable service/version detection
        -t/--threads : Number of concurrent threads (1-300) (default: 20)

    Enforces:
        - Minimum thread count of 1
        - Upper bound of 300 threads to prevent resource exhaustion

    Returns:
        Parsed argparse.Namespace object.
    """

    parser = argparse.ArgumentParser(
        description=(
            "TCPrax - Custom TCP Scanner\n\n"
            "Example Usage:\n"
            "  sudo python3 main.py example.com -p 1-1000 -sS -sV -t 10\n"
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

    args = parser.parse_args()

    # Thread safety validation to prevent excessive resource consumption
    if args.threads < 1:
        parser.error("Thread count must be at least 1.")

    if args.threads > 300:
        parser.error(
            "Thread count too high. Risk of resource exhaustion (>300).")

    return args
