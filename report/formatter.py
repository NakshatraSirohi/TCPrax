"""
Report Formatting Module

Builds human-readable scan reports from structured scan data.

Responsibilities:
- Format the pre-scan configuration summary
- Format per-port result lines (with optional service details)
- Compute and format post-scan performance metrics
- Assemble the complete plain-text report

Formatting is kept separate from both the scan engines and file I/O so
the same report can be printed to the terminal, written to disk, or
rendered in additional formats (e.g. JSON) in the future.
"""

from typing import Dict, List


def build_metrics(results: List[Dict], total_time: float) -> Dict:
    """
    Computes post-scan performance metrics.

    Parameters:
        results: Scan result dictionaries (one per port)
        total_time: Total scan duration in seconds

    Returns:
        Dictionary containing:
            total_time
            scan_rate     (ports per second)
            state_counts  (mapping of port state -> number of ports)
    """

    state_counts = {}
    for result in results:
        state_counts[result["state"]] = state_counts.get(result["state"],
                                                         0) + 1

    scan_rate = len(results) / total_time if total_time > 0 else 0

    return {
        "total_time": total_time,
        "scan_rate": scan_rate,
        "state_counts": state_counts
    }


def format_summary(meta: Dict) -> List[str]:
    """
    Formats the scan configuration summary.

    Expected meta keys:
        target, resolved_ip, scan_type, threads,
        total_ports, service_detection, retries (optional)

    Returns:
        List of report lines (ends with a blank separator line).
    """
    lines = [
        "=== TCPrax Scan Summary ===",
        f"Target          : {meta['target']}",
        f"Resolved IP     : {meta['resolved_ip']}",
        f"Scan Type       : {meta['scan_type']}",
        f"Threads Used    : {meta['threads']}",
        f"Total Ports     : {meta['total_ports']}",
        f"Service Detect  : "
        f"{'Enabled' if meta['service_detection'] else 'Disabled'}",
    ]

    if "retries" in meta:
        lines.append(f"Retries         : {meta['retries']}")

    lines.append("")
    return lines


def format_result(result: Dict, service_detection: bool) -> str:
    """
    Formats a single port result.

    Service information is appended only when service detection
    is enabled and a service entry exists for the port.
    """
    line = f"{result['port']:5d}/tcp  {result['state']}"
    if service_detection and "service" in result:
        line += f"\n{result['service']}\n"
    return line


def format_results(results: List[Dict], service_detection: bool) -> List[str]:
    """
    Formats all port results in the order provided (sorted by port
    by the scan engines).
    """
    return [format_result(result, service_detection) for result in results]


def format_metrics(metrics: Dict) -> List[str]:
    """
    Formats post-scan performance metrics.

    Open/Closed/Filtered counts are always shown; Other/Error counts
    are shown only when non-zero so that the totals add up.

    Returns:
        List of report lines (starts with a blank separator line).
    """
    counts = metrics["state_counts"]

    lines = [
        "",
        "=== Scan Completed ===",
        f"Total Time      : {metrics['total_time']:.3f} seconds",
        f"Scan Rate       : {metrics['scan_rate']:.2f} ports/sec",
        f"Open Ports      : {counts.get('OPEN', 0)}",
        f"Closed Ports    : {counts.get('CLOSED', 0)}",
        f"Filtered Ports  : {counts.get('FILTERED', 0)}",
    ]

    if counts.get("OTHER", 0):
        lines.append(f"Other Ports     : {counts['OTHER']}")
    if counts.get("ERROR", 0):
        lines.append(f"Error Ports     : {counts['ERROR']}")

    return lines


def format_text_report(meta: Dict, results: List[Dict], metrics: Dict) -> str:
    """
    Assembles the complete plain-text scan report.

    The report mirrors the terminal output:
        1. Scan configuration summary
        2. Per-port results (with service info when -sV is enabled)
        3. Performance metrics

    Returns:
        Report text terminated by a newline.
    """
    lines = (format_summary(meta) +
             format_results(results, meta["service_detection"]) +
             format_metrics(metrics))
    return "\n".join(lines) + "\n"
