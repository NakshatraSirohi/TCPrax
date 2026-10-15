"""
Scan Configuration Model

The single configuration object shared by the CLI and GUI. Both
interfaces build one of these and hand it to the scan controller; no
scan parameter is duplicated or re-parsed downstream.

It validates itself using the shared rules in application.validation and
derives the concrete values the core needs (resolved port list, effective
worker count, scan-type flag).
"""

from dataclasses import dataclass
from typing import List, Optional

from .events import ScanConfigurationError
from .validation import (MAX_THREADS, MIN_THREADS, get_top_ports,
                         parse_ports, resolve_workers)


# Scan-type identifiers (interface-neutral).
class ScanType:
    CONNECT = "connect"
    SYN = "syn"


# Port-selection modes.
class PortMode:
    CUSTOM = "custom"
    TOP = "top"


_SCAN_FLAGS = {ScanType.CONNECT: "-sT", ScanType.SYN: "-sS"}


@dataclass
class ScanConfiguration:
    """
    Complete description of a scan, independent of interface.

    Fields:
        target: Hostname or IPv4 address
        scan_type: ScanType.CONNECT or ScanType.SYN
        ports: Custom port spec string (e.g. "1-1000,8080"), or None
        top_ports: Number of common ports to scan, or None
        threads: Worker count, or None for adaptive selection
        service_detection: Whether to run -sV service detection
        retries: Additional probes for uncertain (FILTERED/OTHER) ports
        output_path: File to save the report to, or None

    Exactly one of `ports` or `top_ports` must be set (mutually
    exclusive, mirroring the CLI).
    """
    target: str
    scan_type: str = ScanType.CONNECT
    ports: Optional[str] = None
    top_ports: Optional[int] = None
    threads: Optional[int] = None
    service_detection: bool = False
    retries: int = 0
    output_path: Optional[str] = None

    @property
    def port_mode(self) -> str:
        """Which port-selection mode this configuration uses."""
        return PortMode.TOP if self.top_ports is not None else PortMode.CUSTOM

    def scan_flag(self) -> str:
        """CLI-style scan flag ('-sT' / '-sS') for the chosen scan type."""
        return _SCAN_FLAGS[self.scan_type]

    def validate(self) -> None:
        """
        Validates every field, raising ScanConfigurationError on the
        first problem (so a caller can surface a single clear message).
        """
        if not self.target or not self.target.strip():
            raise ScanConfigurationError("Target must not be empty.")

        if self.scan_type not in (ScanType.CONNECT, ScanType.SYN):
            raise ScanConfigurationError(
                f"Unknown scan type: {self.scan_type!r}")

        # Port selection: exactly one of ports / top_ports.
        if self.ports is not None and self.top_ports is not None:
            raise ScanConfigurationError(
                "Specify either custom ports or top-ports, not both.")
        if self.ports is None and self.top_ports is None:
            raise ScanConfigurationError(
                "No ports selected: set custom ports or top-ports.")

        # Reuse the shared validators (raise ValueError -> config error).
        try:
            if self.top_ports is not None:
                get_top_ports(self.top_ports)
            else:
                parse_ports(self.ports)
        except ValueError as exc:
            raise ScanConfigurationError(str(exc)) from exc

        if self.threads is not None:
            if not MIN_THREADS <= self.threads <= MAX_THREADS:
                raise ScanConfigurationError(
                    f"Thread count must be {MIN_THREADS}-{MAX_THREADS}.")

        if self.retries < 0:
            raise ScanConfigurationError("Retries must be >= 0.")

        if self.output_path is not None and not self.output_path.strip():
            raise ScanConfigurationError("Output path must not be empty.")

    def resolved_ports(self) -> List[int]:
        """Returns the concrete, sorted port list for this configuration."""
        if self.top_ports is not None:
            return get_top_ports(self.top_ports)
        return parse_ports(self.ports)

    def effective_workers(self, port_count: Optional[int] = None) -> int:
        """
        Returns the worker count to use, honouring an explicit thread
        count or sizing adaptively to the workload.
        """
        if port_count is None:
            port_count = len(self.resolved_ports())
        return resolve_workers(self.threads, port_count, self.scan_flag())

    @classmethod
    def from_namespace(cls, args) -> "ScanConfiguration":
        """
        Builds a configuration from a parsed argparse Namespace (the CLI
        adapter path). Mirrors the CLI's own scan-type resolution.
        """
        scan_type = ScanType.SYN if getattr(args, "sS", False) else \
            ScanType.CONNECT
        return cls(
            target=args.host,
            scan_type=scan_type,
            ports=args.ports,
            top_ports=args.top_ports,
            threads=args.threads,
            service_detection=getattr(args, "sV", False),
            retries=getattr(args, "retries", 0),
            output_path=getattr(args, "output", None))
