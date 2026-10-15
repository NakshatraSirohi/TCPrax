"""
RTT Estimator (RFC 6298 style)

Maintains a smoothed round-trip-time estimate and its variation from a
stream of RTT samples, and derives a retransmission-timeout value (RTO)
the same way TCP does. The class is pure and deterministic: it performs
no I/O and needs no sockets, so it can be unit-tested with synthetic
samples alone.

Equations (all times in seconds):

    First valid sample R0:
        SRTT   = R0
        RTTVAR = R0 / 2
        RTO    = SRTT + K * RTTVAR

    Each later valid sample Rn (RTTVAR is updated *before* SRTT):
        RTTVAR = (1 - BETA)  * RTTVAR + BETA  * |SRTT - Rn|
        SRTT   = (1 - ALPHA) * SRTT   + ALPHA * Rn
        RTO    = SRTT + K * RTTVAR

with ALPHA = 1/8, BETA = 1/4, K = 4.

The RTO produced here is the raw statistical estimate. Clamping it to a
usable scan timeout is the timeout policy's responsibility (see
core/timeout.py), so the mathematics and the policy stay independent
(a single unusual sample is smoothed here; hard limits are applied
there).
"""

import math

# RFC 6298 smoothing constants.
ALPHA = 1 / 8   # SRTT gain
BETA = 1 / 4    # RTTVAR gain
K = 4           # RTTVAR multiplier in the RTO formula

# Confidence tiers, by number of valid samples seen.
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
_MEDIUM_AFTER = 3
_HIGH_AFTER = 8


class RTTEstimator:
    """
    Smoothed RTT / RTT-variation estimator producing an RTO.

    Usable on its own without any network access:

        est = RTTEstimator()
        est.update(0.020)
        est.rto          # -> current RTO estimate in seconds
        est.reset()
    """

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Clears all state back to "no samples seen"."""
        self._srtt = None
        self._rttvar = None
        self._count = 0

    # ---- inputs ----
    def update(self, rtt: float) -> bool:
        """
        Feeds one RTT sample (seconds) into the estimator.

        Only finite, strictly positive samples are accepted; anything
        else (zero, negative, NaN, inf, None) is ignored so a bad
        measurement can never corrupt the estimate.

        Returns:
            True if the sample was accepted, False if it was rejected.
        """
        if rtt is None or not math.isfinite(rtt) or rtt <= 0:
            return False

        if self._count == 0:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            # RFC 6298: update RTTVAR from the *old* SRTT, then SRTT.
            self._rttvar = ((1 - BETA) * self._rttvar
                            + BETA * abs(self._srtt - rtt))
            self._srtt = (1 - ALPHA) * self._srtt + ALPHA * rtt

        self._count += 1
        return True

    # ---- outputs ----
    @property
    def rto(self):
        """Raw RTO estimate in seconds, or None before the first sample."""
        if self._count == 0:
            return None
        return self._srtt + K * self._rttvar

    @property
    def srtt(self):
        """Smoothed RTT in seconds, or None before the first sample."""
        return self._srtt

    @property
    def rttvar(self):
        """RTT variation in seconds, or None before the first sample."""
        return self._rttvar

    @property
    def count(self) -> int:
        """Number of valid samples accepted so far."""
        return self._count

    @property
    def confidence(self) -> str:
        """Confidence tier (LOW / MEDIUM / HIGH) from the sample count."""
        if self._count >= _HIGH_AFTER:
            return HIGH
        if self._count >= _MEDIUM_AFTER:
            return MEDIUM
        return LOW
