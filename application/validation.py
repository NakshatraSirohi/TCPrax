"""
Input Parsing and Validation

Pure functions shared by the CLI and GUI for turning user input into
validated scan parameters. This lives in the application layer (not the
CLI) so both interfaces reuse exactly the same rules and the CLI can
become a thin adapter without an import cycle.

None of these functions perform I/O or scanning.
"""

from data.top_tcp_ports import MAX_TOP_PORTS, TOP_TCP_PORTS

# Concurrency bounds (safety limits shared by both interfaces).
MIN_THREADS = 1
MAX_THREADS = 300

# Base worker counts used when the user does not specify a thread count.
# Connect scans are lightweight per worker; SYN workers each hold a raw
# socket, so the SYN base is smaller. Both stay within MAX_THREADS.
ADAPTIVE_CONNECT_BASE = 100
ADAPTIVE_SYN_BASE = 50


def parse_ports(port_string: str) -> list[int]:
    """
    Parses a user-supplied port specification string.

    Supported formats:
        - Single port: "80"
        - Range: "1-1000"
        - Comma-separated: "22,80,443"
        - Mixed: "1-20,40-75"

    Behavior:
        - Expands ranges inclusively.
        - Deduplicates ports using a set.
        - Validates port range (1-65535).
        - Returns a sorted list of ports.

    Raises:
        ValueError for invalid ranges, non-integers or out-of-bound ports.
    """
    if port_string is None or not port_string.strip():
        raise ValueError("No ports specified.")

    ports = set()

    for part in port_string.split(","):
        part = part.strip()
        if not part:
            raise ValueError("Empty port entry.")

        if "-" in part:
            start_str, _, end_str = part.partition("-")
            try:
                start = int(start_str.strip())
                end = int(end_str.strip())
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")

            if start > end:
                raise ValueError(f"Invalid port range: '{part}'")

            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid port: '{part}'")

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def get_top_ports(count: int) -> list[int]:
    """
    Returns the `count` most common TCP ports from the TCPrax
    common-port dataset (data/top_tcp_ports.py), sorted by port.

    Raises:
        ValueError if count is outside 1..MAX_TOP_PORTS.
    """
    if not 1 <= count <= MAX_TOP_PORTS:
        raise ValueError(f"Top-ports count must be 1-{MAX_TOP_PORTS}.")

    return sorted(TOP_TCP_PORTS[:count])


def resolve_workers(requested: "int | None", num_ports: int,
                    scan_type: str) -> int:
    """
    Determines the effective worker count for a scan.

    Parameters:
        requested: The user's thread count, or None if not given
        num_ports: Number of ports to be scanned
        scan_type: "-sT" or "-sS"

    Behavior:
        - An explicit value is honoured (already range validated) and
          acts as an override.
        - Otherwise a bounded default is chosen from the workload: never
          more workers than ports, never above the safety cap, sized by
          scan type.

    Returns:
        Worker count within [MIN_THREADS, MAX_THREADS].
    """
    if requested is not None:
        return requested

    if num_ports <= 0:
        return MIN_THREADS

    base = ADAPTIVE_SYN_BASE if scan_type == "-sS" else ADAPTIVE_CONNECT_BASE
    return max(MIN_THREADS, min(base, num_ports, MAX_THREADS))
