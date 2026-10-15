"""
Service Result Model

Structured representation of a service-detection outcome, plus rendering
to the concise string that -sV displays.

Keeping a structured result (rather than only a formatted string) lets
the detection engine reason about confidence and evidence, while the
presentation layer decides how much to show. The scan result dictionary
still carries a plain "service" string (produced by format_service), so
existing output and tests remain compatible.
"""

from dataclasses import dataclass
from typing import Optional

# Confidence levels, ordered weakest to strongest.
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

_CONFIDENCE_RANK = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

# Where an identification came from (evidence type), not the data source.
DETECTION_BANNER = "banner"
DETECTION_REGEX = "regex"
DETECTION_TLS = "tls"

UNKNOWN = "unknown"


def confidence_rank(level: str) -> int:
    """Numeric rank of a confidence level (higher is stronger)."""
    return _CONFIDENCE_RANK.get(level, -1)


@dataclass(frozen=True)
class ServiceResult:
    """
    A normalized service identification for one port.

    Fields:
        port: TCP port the result describes
        service: Identified service name (e.g. "http"), or "unknown"
        product: Product/software name if extracted, else None
        version: Version string if extracted, else None
        extra_info: Additional info (e.g. protocol details), else None
        confidence: LOW / MEDIUM / HIGH
        detection_source: How it was identified (banner/regex/tls)
        data_source: Which dataset the matching fingerprint came from
                     (e.g. "tcprax", "nmap-service-probes", "iana")
    """
    port: int
    service: str = UNKNOWN
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    confidence: str = CONFIDENCE_LOW
    detection_source: str = DETECTION_REGEX
    data_source: Optional[str] = None

    def is_identified(self) -> bool:
        """True when a concrete service (not 'unknown') was identified."""
        return self.service != UNKNOWN


def format_service(result: ServiceResult) -> str:
    """
    Renders a ServiceResult as the concise string shown by -sV.

    Format (fields omitted when unknown):
        [service] product version (extra) conf:LEVEL

    Product/version are only shown when actually extracted, so a
    service known without a version never implies a made-up version.
    """
    parts = [f"[{result.service}]"]

    if result.product:
        parts.append(result.product)
    if result.version:
        parts.append(result.version)
    if result.extra_info:
        parts.append(f"({result.extra_info})")

    parts.append(f"conf:{result.confidence}")
    return " ".join(parts)
