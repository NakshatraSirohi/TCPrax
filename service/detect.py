"""
Service Detection Orchestration

Runs service/version detection concurrently over the OPEN ports found by
a scan, using a dedicated bounded worker pool.

This layer is kept separate from both the port-scan engines and the
banner-grabbing logic:
- The scan engines decide which ports are OPEN.
- banner.discover_service performs the actual TLS / probe / fingerprint
  work for a single port (unchanged).
- This module only schedules that work and merges each result back onto
  the correct port dictionary.

The service-detection pool is bounded independently of the main port-scan
worker count, so enabling -sV never changes the scan's concurrency limit.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List

from .banner import discover_service

# Upper bound on concurrent service-detection workers. Detection is
# network I/O bound (TLS handshakes, banner reads), so a modest pool
# overlaps the waiting without spawning an unbounded number of threads.
MAX_SERVICE_WORKERS = 20


def service_worker_count(open_ports: int,
                         cap: int = MAX_SERVICE_WORKERS) -> int:
    """
    Chooses a bounded worker count for service detection.

    Never exceeds `cap`, never exceeds the number of OPEN ports, and is
    at least 1 when there is work to do.
    """
    if open_ports <= 0:
        return 0
    return max(1, min(cap, open_ports))


def detect_services(target_ip: str,
                    results: List[Dict],
                    cap: int = MAX_SERVICE_WORKERS,
                    detector: Callable[[str, int], str] = discover_service
                    ) -> List[Dict]:
    """
    Populates the "service" field for every OPEN port, concurrently.

    Parameters:
        target_ip: Resolved target IPv4 address
        results: Scan result dictionaries (mutated in place)
        cap: Maximum concurrent service-detection workers
        detector: Callable(target_ip, port) -> service string
                  (injectable for testing; defaults to discover_service)

    Behavior:
        - Only OPEN ports are probed.
        - Each service string is merged back onto its own result dict.
        - Result identity and ordering are preserved (the same list is
          returned, still sorted by port if it was on input).

    Returns:
        The same `results` list, with "service" set on OPEN ports.
    """

    open_results = [r for r in results if r["state"] == "OPEN"]
    if not open_results:
        return results

    workers = service_worker_count(len(open_results), cap)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Map each future to the result dict it belongs to, so the
        # service string is merged back onto the correct port.
        future_to_result = {
            executor.submit(detector, target_ip, result["port"]): result
            for result in open_results
        }

        for future, result in future_to_result.items():
            outcome = future.result()
            # A detector may return a plain display string, or a
            # structured dict (with a "display" string plus fields). In
            # the structured case, keep the string in "service" for
            # backward compatibility and attach the details separately.
            if isinstance(outcome, dict):
                result["service"] = outcome.get("display", "")
                result["service_info"] = outcome
            else:
                result["service"] = outcome

    return results
