"""
Service Fingerprint Database

Assembles every fingerprint source into a single matching engine and
provides identification with port-based candidate prioritisation.

Sources (all matched by one engine):
    TCPRAX_FINGERPRINTS  - TCPrax-native, MIT (source="tcprax")
    NMAP_FINGERPRINTS    - curated Nmap-derived, NPSL (source="nmap-...")

Port usage: a port only *prioritises* likely fingerprints; it
is never treated as proof of a service. If the likely candidates do not
match, a full sweep runs, so a service on a non-standard port is still
identified from its response.
"""

from functools import lru_cache
from typing import Optional

from .common_services import tcp_port_hints
from .fingerprint_data import PORT_SERVICE_HINTS, TCPRAX_FINGERPRINTS
from .fingerprints import FingerprintEngine
from .nmap_fingerprints import NMAP_FINGERPRINTS
from .result import DETECTION_REGEX, ServiceResult

# Port -> candidate fingerprint services. Broad coverage from the curated
# common-service catalog, with the hand-tuned native hints taking
# precedence for core ports.
_PORT_HINTS = {**tcp_port_hints(), **PORT_SERVICE_HINTS}


def all_fingerprints() -> list:
    """Returns the combined fingerprint list from every source."""
    return list(TCPRAX_FINGERPRINTS) + list(NMAP_FINGERPRINTS)


@lru_cache(maxsize=1)
def get_engine() -> FingerprintEngine:
    """Returns the shared engine, compiling fingerprints once."""
    return FingerprintEngine(all_fingerprints())


def candidate_services(port: int) -> Optional[set]:
    """Likely services for a port (probe/fingerprint prioritisation)."""
    hints = _PORT_HINTS.get(port)
    return set(hints) if hints else None


def identify(data: bytes,
             port: int,
             detection_source: str = DETECTION_REGEX
             ) -> Optional[ServiceResult]:
    """
    Identifies a service from a response, prioritising likely services.

    Tries the port's candidate fingerprints first (fast path); if none
    match, sweeps the full database so non-standard-port services are
    still identified. Returns None when nothing matches.
    """
    engine = get_engine()

    candidates = candidate_services(port)
    if candidates:
        result = engine.match(data, port, detection_source,
                              services=candidates)
        if result is not None:
            return result

    return engine.match(data, port, detection_source)
