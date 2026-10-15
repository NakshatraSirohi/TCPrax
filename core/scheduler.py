"""
Bounded Task Scheduler

Runs one callable per port across a bounded thread pool and returns the
results sorted by port.

Both scan engines share this scheduler so the concurrency pattern lives
in one place (consistent worker bounding, result collection and
ordering). It keeps at most a bounded number of futures in flight at
once: for a small port set every task is submitted immediately (identical
to submitting them all up front), but for a very large port set the
number of pending Future/task objects is capped at a small multiple of
the worker count instead of growing with the number of ports.

Determinism: tasks execute concurrently and complete in arbitrary order,
but the returned list is always sorted by the "port" field of each
result, so output ordering does not depend on completion timing.
"""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable, Dict, Iterable, List, Optional

# In-flight futures are capped at workers * PENDING_FACTOR so a large
# scan does not materialise one Future per port simultaneously.
PENDING_FACTOR = 4


def run_port_tasks(ports: Iterable[int],
                   task_fn: Callable[[int], Dict],
                   workers: int,
                   pending_factor: int = PENDING_FACTOR,
                   on_result: Optional[Callable[[Dict], None]] = None,
                   should_cancel: Optional[Callable[[], bool]] = None
                   ) -> List[Dict]:
    """
    Executes task_fn(port) for every port using a bounded thread pool.

    Parameters:
        ports: Ports to scan (any iterable; consumed once)
        task_fn: Callable mapping a port to its result dictionary
        workers: Maximum concurrent worker threads
        pending_factor: Max in-flight futures = workers * pending_factor
        on_result: Optional callback invoked (on the scheduler thread) as
                   each result completes - used for streaming progress.
        should_cancel: Optional predicate polled between completions;
                   when it returns True, no further tasks are submitted,
                   in-flight tasks are allowed to finish, and the partial
                   results collected so far are returned.

    Returns:
        Result dictionaries sorted by their "port" field. On cancellation
        this is the partial set of results that had completed.
    """

    ports = list(ports)
    results: List[Dict] = []
    if not ports:
        return results

    workers = max(1, workers)
    max_pending = max(workers * pending_factor, workers)

    def cancelled() -> bool:
        return should_cancel is not None and should_cancel()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        port_iter = iter(ports)
        in_flight = set()

        # Prime the pool with the first batch of tasks (unless already
        # cancelled before we started).
        if not cancelled():
            for port in port_iter:
                in_flight.add(executor.submit(task_fn, port))
                if len(in_flight) >= max_pending:
                    break

        # As tasks finish, collect their results and top up the pool so
        # roughly `max_pending` tasks stay in flight until ports run out.
        while in_flight:
            done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)

            for future in done:
                result = future.result()
                results.append(result)
                if on_result is not None:
                    on_result(result)

            # Stop scheduling new work once cancelled; let in-flight
            # tasks drain so no thread is killed mid-probe.
            if cancelled():
                continue

            for port in port_iter:
                in_flight.add(executor.submit(task_fn, port))
                if len(in_flight) >= max_pending:
                    break

    # Deterministic output ordering regardless of completion order.
    results.sort(key=lambda result: result["port"])
    return results
