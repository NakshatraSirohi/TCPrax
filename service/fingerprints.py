"""
Service Fingerprint Model and Matching Engine

A single normalized representation for service fingerprints, whatever
their origin (TCPrax-native signatures, Nmap-derived fingerprints, or
common-service hints). One engine matches them all, so no source needs
its own matching code.

Fingerprints match against raw response *bytes* (like Nmap), so binary
protocols and control characters work correctly. Extracted capture
groups are decoded for display only.

Safety: patterns are compiled once when an engine is built. A pattern
that fails to compile (or looks prone to catastrophic backtracking) is
recorded in `engine.errors` and skipped, so one bad fingerprint never
crashes detection or breaks the rest of the database.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .result import (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM,
                     DETECTION_REGEX, ServiceResult, confidence_rank)

# Data-source tags (which dataset a fingerprint came from).
SOURCE_TCPRAX = "tcprax"
SOURCE_NMAP = "nmap-service-probes"
SOURCE_IANA = "iana"

# Cap on how much response data is matched, to bound worst-case regex
# cost regardless of how much a service sends.
MAX_MATCH_BYTES = 4096


class FingerprintError(Exception):
    """Raised when a fingerprint cannot be compiled or is unsafe."""


@dataclass(frozen=True)
class ServiceFingerprint:
    """
    One normalized fingerprint.

    Fields:
        service: Normalized service name (e.g. "http", "ssh")
        pattern: Byte regex matched against the response
        flags: re flags (e.g. re.IGNORECASE | re.DOTALL)
        product/version/info: Optional templates using $1..$9 capture
                              references; None when not extractable
        confidence: Confidence ceiling for this fingerprint
                    (a soft/broad fingerprint caps lower)
        priority: Lower is tried first (hard matches before soft)
        source: Dataset tag (SOURCE_TCPRAX / SOURCE_NMAP / SOURCE_IANA)
        name: Optional identifier for dedup/debugging
    """
    service: str
    pattern: bytes
    flags: int = 0
    product: Optional[str] = None
    version: Optional[str] = None
    info: Optional[str] = None
    confidence: str = CONFIDENCE_MEDIUM
    priority: int = 50
    source: str = SOURCE_TCPRAX
    name: Optional[str] = None


# Detects a few obviously dangerous shapes (nested unbounded quantifiers)
# that can trigger catastrophic backtracking, e.g. (a+)+ or (a*)* .
_CATASTROPHIC = re.compile(rb"\([^)]*[+*]\)[+*]")


def looks_catastrophic(pattern: bytes) -> bool:
    """Heuristic: True if a pattern has a risky nested quantifier."""
    return _CATASTROPHIC.search(pattern) is not None


def compile_fingerprint(fp: ServiceFingerprint) -> "re.Pattern[bytes]":
    """
    Compiles a fingerprint's pattern to a byte regex.

    Raises:
        FingerprintError on invalid syntax or a catastrophic shape.
    """
    if not isinstance(fp.pattern, (bytes, bytearray)):
        raise FingerprintError(
            f"{fp.service}: pattern must be bytes, got {type(fp.pattern).__name__}")

    if looks_catastrophic(fp.pattern):
        raise FingerprintError(
            f"{fp.service}: pattern risks catastrophic backtracking")

    try:
        return re.compile(fp.pattern, fp.flags)
    except re.error as exc:
        raise FingerprintError(f"{fp.service}: invalid regex: {exc}") from exc


_TEMPLATE_REF = re.compile(r"\$([0-9])")


def expand_template(template: Optional[str],
                    match: "re.Match[bytes]") -> Optional[str]:
    """
    Expands a product/version/info template using capture groups.

    Replaces $1..$9 with the corresponding decoded capture group. If the
    template references an unsupported helper (any other $-expression),
    the field is dropped (returns None) rather than emitting template
    junk or an invented value.

    Returns:
        Expanded string, or None if empty / unsupported / unavailable.
    """
    if not template:
        return None

    def replace(ref: "re.Match[str]") -> str:
        index = int(ref.group(1))
        try:
            group = match.group(index)
        except (IndexError, re.error):
            return ""
        if group is None:
            return ""
        return group.decode("utf-8", errors="replace")

    expanded = _TEMPLATE_REF.sub(replace, template)

    # Any leftover '$' means an unsupported helper we did not expand.
    if "$" in expanded:
        return None

    expanded = expanded.strip()
    return expanded or None


def _result_confidence(fp: ServiceFingerprint, product: Optional[str],
                       version: Optional[str]) -> str:
    """
    Confidence from evidence, capped by the fingerprint's ceiling.

    Strong evidence (a version) proposes HIGH, a product proposes at
    least MEDIUM; the final level never exceeds the fingerprint's own
    confidence ceiling (so a broad/soft fingerprint stays low even when
    it happens to capture text).
    """
    if version:
        proposed = CONFIDENCE_HIGH
    elif product:
        proposed = CONFIDENCE_MEDIUM
    else:
        proposed = fp.confidence

    if confidence_rank(proposed) <= confidence_rank(fp.confidence):
        return proposed
    return fp.confidence


class FingerprintEngine:
    """
    Compiles a set of fingerprints and matches responses against them.

    Fingerprints are ordered by priority (hard matches first) so the
    first match found is the strongest applicable one, giving early
    termination. Fingerprints can be pre-filtered by candidate service
    to avoid matching irrelevant patterns.
    """

    def __init__(self, fingerprints: List[ServiceFingerprint]):
        self._compiled: List[Tuple[ServiceFingerprint, "re.Pattern[bytes]"]] = []
        self.errors: List[Tuple[ServiceFingerprint, str]] = []
        self._by_service: Dict[str, int] = {}

        for fp in sorted(fingerprints, key=lambda f: f.priority):
            try:
                regex = compile_fingerprint(fp)
            except FingerprintError as exc:
                self.errors.append((fp, str(exc)))
                continue
            self._compiled.append((fp, regex))
            self._by_service[fp.service] = self._by_service.get(fp.service,
                                                                0) + 1

    def __len__(self) -> int:
        return len(self._compiled)

    @property
    def services(self) -> List[str]:
        """Sorted list of services the engine can identify."""
        return sorted(self._by_service)

    def match(self,
              data: bytes,
              port: int,
              detection_source: str = DETECTION_REGEX,
              services: Optional[set] = None) -> Optional[ServiceResult]:
        """
        Returns the strongest matching ServiceResult, or None.

        Parameters:
            data: Raw response bytes
            port: Port the response came from (recorded on the result)
            detection_source: Evidence type recorded on the result
            services: If given, only fingerprints for these services are
                      tried (candidate pre-selection from port hints)
        """
        if not data:
            return None

        window = data[:MAX_MATCH_BYTES]

        for fp, regex in self._compiled:
            if services is not None and fp.service not in services:
                continue

            found = regex.search(window)
            if not found:
                continue

            product = expand_template(fp.product, found)
            version = expand_template(fp.version, found)
            info = expand_template(fp.info, found)

            return ServiceResult(
                port=port,
                service=fp.service,
                product=product,
                version=version,
                extra_info=info,
                confidence=_result_confidence(fp, product, version),
                detection_source=detection_source,
                data_source=fp.source)

        return None
