"""
Port State Module

Central interpretation layer for TCPrax probe results. Scan engines
perform the probes; this module decides what each observation means
and how multiple observations combine.

Provides:
- Port state definitions
- Classification of SYN-scan responses (TCP flags)
- Classification of connect() results (errno values)
- Aggregation of retry observations into a final state

User-visible states:
    OPEN      : Target accepted the connection / answered SYN-ACK
    CLOSED    : Target actively refused (RST)
    FILTERED  : No usable response before timeout, or unreachable
    OTHER     : A response that fits none of the categories above
    ERROR     : Local failure prevented the probe from completing

Retry aggregation:
    Only uncertain states (FILTERED, OTHER) are retried. When multiple
    observations of a port disagree, the final state is chosen by the
    precedence OPEN > CLOSED > FILTERED > OTHER. ERROR is ranked last,
    since it records a local failure rather than a network observation.
"""

import errno
import socket
from typing import Iterable
from .parse_tcp_packet import ACK, RST, SYN

OPEN = "OPEN"
CLOSED = "CLOSED"
FILTERED = "FILTERED"
OTHER = "OTHER"
ERROR = "ERROR"

# States eligible for additional probing via --retries
RETRYABLE_STATES = frozenset({FILTERED, OTHER})

# Final-state precedence when observations disagree (highest first)
STATE_PRECEDENCE = (OPEN, CLOSED, FILTERED, OTHER, ERROR)

_RANK = {state: rank for rank, state in enumerate(STATE_PRECEDENCE)}

# Unrecognised states rank between OTHER and ERROR
_UNKNOWN_RANK = _RANK[OTHER] + 0.5


# connect() errno values meaning "no usable answer from the port":
# timeouts (Python reports a connect_ex() timeout as EAGAIN/EWOULDBLOCK)
# and ICMP unreachable replies, including administratively prohibited,
# which Linux reports as EHOSTUNREACH / ENETUNREACH.
_CONNECT_FILTERED_ERRNOS = frozenset({
    errno.EAGAIN,
    errno.EWOULDBLOCK,
    errno.ETIMEDOUT,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
})

# connect() errno values caused by the local system rather than the
# target: permissions / local firewall, resource exhaustion, local
# address problems and a downed local interface.
_CONNECT_ERROR_ERRNOS = frozenset({
    errno.EACCES,
    errno.EPERM,
    errno.EADDRINUSE,
    errno.EADDRNOTAVAIL,
    errno.EMFILE,
    errno.ENFILE,
    errno.ENOBUFS,
    errno.ENOMEM,
    errno.ENETDOWN,
})


def classify_syn_response(flags: int) -> str:
    """
    Classifies a validated reply to a SYN probe by its TCP flags.

    The caller must already have matched the segment to the probe
    (addresses, ports, acknowledgment number).

    Classification:
        RST (without SYN)     : CLOSED
        SYN + ACK (no RST)    : OPEN
        Anything else         : OTHER (e.g. bare SYN, bare ACK,
                                SYN + RST)
    """
    if flags & RST:
        return OTHER if flags & SYN else CLOSED

    if (flags & (SYN | ACK)) == (SYN | ACK):
        return OPEN

    return OTHER


def classify_connect_result(code: int) -> str:
    """
    Classifies the return value of socket.connect_ex().

    Classification:
        0                          : OPEN
        ECONNREFUSED               : CLOSED
        Timeout / unreachable      : FILTERED
        Local system failures      : ERROR
        Any other errno            : OTHER
    """
    if code == 0:
        return OPEN
    if code == errno.ECONNREFUSED:
        return CLOSED
    if code in _CONNECT_FILTERED_ERRNOS:
        return FILTERED
    if code in _CONNECT_ERROR_ERRNOS:
        return ERROR
    return OTHER


def classify_connect_exception(exc: BaseException) -> str:
    """
    Classifies an exception raised while performing a connect() probe.

    connect_ex() reports network outcomes as return codes, so an
    exception indicates a local failure (e.g. socket creation failed),
    except for an explicit socket timeout.
    """
    if isinstance(exc, socket.timeout):
        return FILTERED
    return ERROR


def is_retryable(state: str) -> bool:
    """Returns True if the state is uncertain and may be re-probed."""
    return state in RETRYABLE_STATES


def resolve_final_state(observations: Iterable[str]) -> str:
    """
    Resolves the final port state from one or more observations.

    Parameters:
        observations: States recorded for each probe attempt

    Returns:
        The highest-precedence observed state.

    Raises:
        ValueError if no observations are supplied.
    """
    observations = list(observations)
    if not observations:
        raise ValueError("At least one observation is required.")

    return min(observations, key=lambda s: _RANK.get(s, _UNKNOWN_RANK))
