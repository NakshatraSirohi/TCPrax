"""
CLI Parsing Module

Responsible for:
- Parsing command-line arguments
- Selecting ports from the common-port dataset (--top-ports)
- Enforcing thread safety constraints

The pure parsing/validation rules (port parsing, top-ports selection,
worker sizing) live in application.validation so the CLI and GUI share
them; this module is the CLI adapter around argparse. It executes no
scanning logic. The shared helpers are re-imported here so existing
`from cli import parse_ports` style imports keep working.
"""

import argparse

from application.validation import (ADAPTIVE_CONNECT_BASE, ADAPTIVE_SYN_BASE,
                                    MAX_THREADS, MAX_TOP_PORTS, MIN_THREADS,
                                    get_top_ports, parse_ports,
                                    resolve_workers)

__all__ = [
    "ADAPTIVE_CONNECT_BASE", "ADAPTIVE_SYN_BASE", "MAX_THREADS",
    "MAX_TOP_PORTS", "MIN_THREADS", "get_top_ports", "parse_ports",
    "resolve_workers", "select_ports", "top_ports_count", "non_negative_int",
    "parse_arguments",
]


def select_ports(args: argparse.Namespace) -> list[int]:
    """
    Resolves the port list from parsed arguments.

    Uses --top-ports when supplied, otherwise the explicit -p/--ports
    specification.
    """
    if args.top_ports is not None:
        return get_top_ports(args.top_ports)

    return parse_ports(args.ports)


def top_ports_count(value: str) -> int:
    """
    argparse type for --top-ports: accepts integers 1..MAX_TOP_PORTS.

    Raises:
        argparse.ArgumentTypeError for non-integers or out-of-range values.
    """
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: '{value}'")

    if not 1 <= number <= MAX_TOP_PORTS:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {MAX_TOP_PORTS} (got {number})")

    return number


def non_negative_int(value: str) -> int:
    """
    argparse type for --retries: accepts integers >= 0.

    Raises:
        argparse.ArgumentTypeError for non-integers or negative values.
    """
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: '{value}'")

    if number < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0 (got {number})")

    return number


def parse_arguments(argv: list[str] | None = None):
    """
    Defines and parses TCPrax command-line interface.

    Arguments:
        host         : Target hostname or IPv4 address
        -p/--ports   : Port specification string
        --top-ports  : Scan the N most common TCP ports (1-1000)
                       (exactly one of -p/--ports or --top-ports is required)
        -sT          : TCP Connect scan
        -sS          : TCP SYN scan (requires root)
        -sV          : Enable service/version detection
        -t/--threads : Number of concurrent threads (1-300)
                       (default: chosen adaptively from the port count)
        -o/--output  : Save the complete scan report to a file
        --retries    : Additional probes for FILTERED/OTHER ports (default: 0)

    Parameters:
        argv: Argument list to parse (defaults to sys.argv[1:])

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
            "  python3 main.py 192.168.1.1 -p 22,80,443 -sT -t 50\n"
            "  sudo python3 main.py example.com -sS --top-ports 100 "
            "--retries 3 -o scan.txt"),
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("host", help="Target host (IP or domain)")

    # Exactly one port-selection method must be supplied
    port_selection = parser.add_mutually_exclusive_group(required=True)

    port_selection.add_argument(
        "-p",
        "--ports",
        help="Port(s) (e.g.: 80; 1-1000; 22,80,443; 1-20,40-75)")

    port_selection.add_argument(
        "--top-ports",
        metavar="N",
        type=top_ports_count,
        help=f"Scan the N most common TCP ports (1-{MAX_TOP_PORTS})")

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
        default=None,
        help=("Number of concurrent threads (1-300). "
              "Default: chosen automatically from the port count"))

    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save the complete scan report to FILE (plain text, e.g. scan.txt)")

    parser.add_argument(
        "--retries",
        metavar="N",
        type=non_negative_int,
        default=0,
        help=("Additional probes for FILTERED/OTHER ports "
              "(default: 0, no additional probing)"))

    args = parser.parse_args(argv)

    # Thread safety validation to prevent excessive resource consumption.
    # Only applies when the user supplies -t; otherwise the count is
    # chosen adaptively (see resolve_workers) within the same bounds.
    if args.threads is not None:
        if args.threads < MIN_THREADS:
            parser.error(f"Thread count must be at least {MIN_THREADS}.")

        if args.threads > MAX_THREADS:
            parser.error("Thread count too high. "
                         f"Risk of resource exhaustion (>{MAX_THREADS}).")

    return args
