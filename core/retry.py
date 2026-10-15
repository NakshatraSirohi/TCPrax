"""
Retry Module

Re-probes ports whose result is uncertain (FILTERED / OTHER).

The retry loop is independent of the scan technique: each engine
supplies a zero-argument probe callable that performs one genuine
network probe and returns the observed state. The same callable is
used for the initial attempt and every retry, so probe logic is never
duplicated.
"""

from typing import Callable, List, Tuple
from .port_state import is_retryable, resolve_final_state


def probe_with_retries(probe: Callable[[], str],
                       retries: int) -> Tuple[str, List[str]]:
    """
    Runs an initial probe followed by up to `retries` additional probes.

    Parameters:
        probe: Callable performing one fresh probe, returning a state
        retries: Maximum number of additional attempts (>= 0)

    Behavior:
        - Always performs the initial probe.
        - Retries only while the resolved state is FILTERED or OTHER.
        - Stops early once a conclusive state (OPEN / CLOSED) is seen.
        - Resolves the final state from all observations.

    Returns:
        (final_state, observations) where observations lists the state
        recorded for every attempt in order.
    """

    if retries < 0:
        raise ValueError("retries must be >= 0")

    observations = [probe()]
    final_state = observations[0]

    while is_retryable(final_state) and len(observations) <= retries:
        observations.append(probe())
        final_state = resolve_final_state(observations)

    return final_state, observations
