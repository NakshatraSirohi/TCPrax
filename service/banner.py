"""
Service Detection and Banner Grabbing Module

Obtains a response from an open port and identifies the service using
the shared fingerprint database (service/database.py).

Layered detection:
1. Passive banner extraction
2. Protocol-aware active probing (PROBE_MAP)
3. Fingerprint matching via the normalized engine (all sources)
4. TLS handshake inspection for encrypted services

This module owns the network I/O and probe selection; it delegates all
classification to the fingerprint engine, so every data source (TCPrax
native, Nmap-derived) is matched by the same code. It performs detection
only on confirmed open ports; it does not scan.
"""

import socket
import ssl
from dataclasses import replace

from .database import identify
from .result import (CONFIDENCE_LOW, DETECTION_BANNER, DETECTION_TLS,
                     ServiceResult, format_service)

READ_SIZE = 1024
CONNECT_TIMEOUT = 2.5
TLS_TIMEOUT = 3.0

# Protocol-aware active probes keyed by common service ports. Used to
# elicit a banner from services that stay silent until spoken to.
PROBE_MAP = {
    80:
    b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    443:
    b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    8080:
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    8443:
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    3128:
    b"CONNECT google.com:443 HTTP/1.1\r\n\r\n",
    21:
    b"\r\n",
    22:
    b"\n",
    23:
    b"\r\n",
    115:
    b"\n",
    25:
    b"EHLO test.com\r\n",
    110:
    b"USER test\r\n",
    143:
    b"A1 CAPABILITY\r\n",
    587:
    b"EHLO test.com\r\n",
    993:
    b"A1 CAPABILITY\r\n",
    995:
    b"USER test\r\n",
    1433:
    b"\x12\x01\x00\x34",
    3306:
    b"\x00\x00\x00\x01",
    5432:
    b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    6379:
    b"INFO\r\n",
    27017:
    b"\x39\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
    9200:
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    53:
    b"\x00\x0c\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00",
    389:
    b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
    445:
    b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00",
    3389:
    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
    5900:
    b"RFB 003.008\n",
    1883:
    b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    5000:
    b"GET / HTTP/1.1\r\n\r\n",
    5672:
    b"AMQP\x00\x00\x09\x01",
    9092:
    b"\x00\x00\x00\x12\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    10000:
    b"GET / HTTP/1.1\r\n\r\n",
    2049:
    b"\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x04",
}

# Ports commonly associated with TLS-wrapped services.
TLS_PORTS = [443, 8443, 993, 995, 465, 587]


def _with_extra(result: ServiceResult, extra: str) -> ServiceResult:
    """Appends text to a result's extra_info field."""
    merged = f"{result.extra_info}; {extra}" if result.extra_info else extra
    return replace(result, extra_info=merged)


def _service_dict(display: str, *, service=None, product=None, version=None,
                  extra_info=None, confidence=None, detection_source=None,
                  data_source=None) -> dict:
    """Builds the structured service dict returned by the -sV pipeline."""
    return {"display": display, "service": service, "product": product,
            "version": version, "extra_info": extra_info,
            "confidence": confidence, "detection_source": detection_source,
            "data_source": data_source}


def _result_dict(result: ServiceResult, display: str) -> dict:
    """Converts an engine ServiceResult plus its display string to a dict."""
    return _service_dict(display, service=result.service,
                         product=result.product, version=result.version,
                         extra_info=result.extra_info,
                         confidence=result.confidence,
                         detection_source=result.detection_source,
                         data_source=result.data_source)


def _classify_result(data: bytes, port: int, detection_source: str) -> dict:
    """
    Identifies a service from response bytes as a structured dict, or
    reports it as unknown (trimmed printable snippet, never port-guessed).
    """
    result = identify(data, port, detection_source)
    if result is not None and result.is_identified():
        return _result_dict(result, format_service(result))

    snippet = data.decode("utf-8", errors="ignore").strip()
    display = f"[unknown] {snippet[:200]}" if snippet \
        else "[unknown] (non-text response)"
    return _service_dict(display, detection_source=detection_source)


def try_tls_result(target_ip: str, port: int) -> "dict | None":
    """
    Attempts a TLS handshake and identifies the service beneath it.

    Extracts the negotiated TLS version and certificate CN, probes once
    over TLS, and classifies the response with the fingerprint engine.

    Returns:
        Structured service dict if TLS succeeds, else None.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port),
                                      timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock,
                                     server_hostname=target_ip) as tls_sock:
                tls_version = tls_sock.version()

                cert = tls_sock.getpeercert() or {}
                subject = dict(x[0] for x in cert.get("subject", []))
                common_name = subject.get("commonName")

                data = b""
                try:
                    tls_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " +
                                     target_ip.encode() + b"\r\n\r\n")
                    data = tls_sock.recv(READ_SIZE)
                except Exception:
                    data = b""

                extra = f"TLS {tls_version}"
                if common_name:
                    extra += f", CN={common_name}"

                result = identify(data, port,
                                  DETECTION_TLS) if data else None
                if result is not None and result.is_identified():
                    merged = _with_extra(result, extra)
                    return _result_dict(merged, format_service(merged))

                # TLS negotiated but the service underneath is unknown.
                base = ServiceResult(port=port, service="ssl",
                                     extra_info=extra,
                                     confidence=CONFIDENCE_LOW,
                                     detection_source=DETECTION_TLS,
                                     data_source="tcprax")
                return _result_dict(base, format_service(base))

    except Exception:
        return None


def _grab_banner(sock: socket.socket, port: int) -> "bytes | None":
    """
    Reads a banner from a connected socket.

    Tries a passive read first, then a port-specific active probe, then a
    generic probe, returning the first non-empty response.
    """
    # Passive banner grab.
    try:
        data = sock.recv(READ_SIZE)
    except (socket.timeout, ConnectionResetError):
        data = b""
    if data:
        return data

    # Protocol-specific active probe.
    if port in PROBE_MAP:
        try:
            sock.sendall(PROBE_MAP[port])
            data = sock.recv(READ_SIZE)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            data = b""
        if data:
            return data

    # Generic newline probe.
    try:
        sock.sendall(b"\r\n\r\n")
        data = sock.recv(READ_SIZE)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        return None
    return data or None


def discover_service_result(target_ip: str, port: int) -> dict:
    """
    Performs service detection on an open TCP port, returning structured
    data (service, product, version, confidence, detection source and a
    ready-to-display string).

    Strategy:
        1. For TLS-associated ports, try TLS first.
        2. Otherwise connect, grab a banner, and classify it via the
           fingerprint engine.
    """
    if port in TLS_PORTS:
        tls_result = try_tls_result(target_ip, port)
        if tls_result:
            return tls_result

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((target_ip, port))
            data = _grab_banner(sock, port)
    except (ConnectionRefusedError, socket.timeout):
        return _service_dict("Connection Failed",
                             detection_source=DETECTION_BANNER)
    except OSError as exc:
        return _service_dict(f"Error: {exc}",
                             detection_source=DETECTION_BANNER)

    if not data:
        return _service_dict("Open Port: Silent (No response to any probe)",
                             detection_source=DETECTION_BANNER)

    return _classify_result(data, port, DETECTION_BANNER)


def discover_service(target_ip: str, port: int) -> str:
    """
    Service detection returning just the display string (used by the CLI
    and as the default detector). Wraps discover_service_result.
    """
    return discover_service_result(target_ip, port)["display"]
