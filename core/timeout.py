"""
Timeout Policy

Turns the RTT estimator's raw RTO into a bounded, usable scan timeout,
and layers a small, bounded backoff on top for stretches of consecutive
probes that get no answer.

The estimation mathematics live in core/rtt.py; this module owns only
*policy*: the [MIN_TIMEOUT, MAX_TIMEOUT] envelope, the cold-start
fallback used before any RTT has been measured, and the timeout backoff.
Keeping the two apart means the arbitrary limits are not buried inside
the estimator.

`AdaptiveTimeout` bundles an `RTTEstimator` with a `TimeoutPolicy` behind
a lock so the concurrent scan engines can share one instance safely:

    adaptive = AdaptiveTimeout()
    adaptive.timeout()          # current per-probe timeout (seconds)
    adaptive.update(rtt)        # feed a valid RTT observation
    adaptive.observe_timeout()  # record a probe that got no answer
    adaptive.reset()
"""

import threading

from .rtt import RTTEstimator

# Policy bounds (seconds). The lower bound is deliberately small so a
# fast LAN can actually benefit from RTT adaptation instead of being
# pinned at a large floor; the upper bound caps the wait on slow or
# unresponsive paths. The fallback is used only until the first valid
# RTT sample arrives.
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 3.0
FALLBACK_TIMEOUT = 1.0

# Consecutive no-answer probes tolerated before the timeout is stretched,
# and the hard cap on the backoff multiplier. The scaled timeout is still
# clamped to MAX_TIMEOUT, so growth is bounded twice over.
BACKOFF_AFTER = 3
BACKOFF_FACTOR_MAX = 8.0


class TimeoutPolicy:
    """
    Maps an RTT estimate to a bounded timeout, with consecutive-timeout
    backoff. Pure and side-effect free: it holds only configuration and
    reads (never mutates) the estimator passed to it.
    """

    def __init__(self,
                 min_timeout: float = MIN_TIMEOUT,
                 max_timeout: float = MAX_TIMEOUT,
                 fallback: float = FALLBACK_TIMEOUT,
                 backoff_after: int = BACKOFF_AFTER,
                 backoff_factor_max: float = BACKOFF_FACTOR_MAX):
        self.min_timeout = min_timeout
        self.max_timeout = max_timeout
        self.fallback = fallback
        self.backoff_after = backoff_after
        self.backoff_factor_max = backoff_factor_max

    def clamp(self, value: float) -> float:
        """Clamps a timeout to the policy's [min, max] envelope."""
        return max(self.min_timeout, min(value, self.max_timeout))

    def base_timeout(self, estimator: RTTEstimator) -> float:
        """
        Bounded timeout from the estimator alone (no backoff). Uses the
        fallback until the estimator has seen at least one valid sample.
        """
        rto = estimator.rto
        return self.clamp(self.fallback if rto is None else rto)

    def backoff_factor(self, consecutive_timeouts: int) -> float:
        """
        Multiplier applied after `backoff_after` consecutive timeouts.

        Returns 1.0 until the threshold is reached, then doubles per
        additional timeout, capped at `backoff_factor_max`.
        """
        extra = consecutive_timeouts - self.backoff_after + 1
        if extra <= 0:
            return 1.0
        return min(self.backoff_factor_max, 2.0 ** extra)

    def timeout(self, estimator: RTTEstimator,
                consecutive_timeouts: int = 0) -> float:
        """Final per-probe timeout: bounded base RTO, scaled by backoff."""
        scaled = self.base_timeout(estimator) \
            * self.backoff_factor(consecutive_timeouts)
        return self.clamp(scaled)


class AdaptiveTimeout:
    """
    Thread-safe adaptive timeout shared by a scan's worker threads.

    Wraps one `RTTEstimator` and one `TimeoutPolicy`, tracking timeout
    events separately from RTT samples. A valid RTT observation both
    updates the estimator and clears the timeout-backoff counter, letting
    the estimate converge again once the target starts responding.
    """

    def __init__(self, policy: "TimeoutPolicy | None" = None):
        self._estimator = RTTEstimator()
        self._policy = policy or TimeoutPolicy()
        self._consecutive_timeouts = 0
        self._lock = threading.Lock()

    def update(self, rtt: float) -> None:
        """Records a valid RTT sample and resets the backoff on success."""
        with self._lock:
            if self._estimator.update(rtt):
                self._consecutive_timeouts = 0

    def observe_timeout(self) -> None:
        """Records one probe that received no matching answer."""
        with self._lock:
            self._consecutive_timeouts += 1

    def timeout(self) -> float:
        """Current per-probe timeout in seconds (bounded, with backoff)."""
        with self._lock:
            return self._policy.timeout(self._estimator,
                                        self._consecutive_timeouts)

    def reset(self) -> None:
        """Clears the estimator and the backoff counter."""
        with self._lock:
            self._estimator.reset()
            self._consecutive_timeouts = 0

    @property
    def confidence(self) -> str:
        with self._lock:
            return self._estimator.confidence

    @property
    def sample_count(self) -> int:
        with self._lock:
            return self._estimator.count
