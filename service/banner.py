"""
Service Detection and Banner Grabbing Module

Implements layered service identification using:

1. Passive banner extraction
2. Protocol-aware active probing
3. Regex-based fingerprint classification
4. TLS handshake inspection for encrypted services

Design Philosophy:
- Attempt TLS first for known encrypted ports.
- Fall back to plain TCP if TLS is unavailable.
- Use protocol-specific probes where applicable.
- Apply signature-based classification to received banners.

This module does not perform scanning — only service identification
on confirmed open ports.
"""

import socket
import ssl
import re

# Regex-based service fingerprints applied to banner text
SIGNATURES = {
    "HTTP Web Server": r"HTTP/\d\.\d|Server: |<html>",
    "SSH (Secure Shell)": r"SSH-\d\.\d-",
    "FTP Server": r"^220.*FTP",
    "SMTP (Mail Server)": r"^220.*SMTP|ESMTP",
    "MySQL Database": r"mysql_native_password|[\d\.]+-MariaDB|[\d\.]+-log",
    "PostgreSQL": r"PostgreSQL",
    "Redis": r"\+PONG|redis_version:",
    "VNC": r"RFB \d{3}\.\d{3}",
    "SMB (Windows File Share)": r"\xffSMB",
}

# Protocol-aware active probes keyed by common service ports
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

# Ports commonly associated with TLS-wrapped services
TLS_PORTS = [443, 8443, 993, 995, 465, 587]


def try_tls(target_ip: str, port: int) -> str | None:
    """
    Attempts TLS handshake on specified port.

    Workflow:
        1. Establish TCP connection.
        2. Perform TLS handshake.
        3. Extract negotiated TLS version.
        4. Extract certificate Common Name (CN).
        5. Optionally attempt HTTP probe over TLS.

    Returns:
        Formatted service description string if TLS succeeds.
        None if TLS handshake fails.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=3) as sock:
            with context.wrap_socket(sock,
                                     server_hostname=target_ip) as tls_sock:
                tls_version = tls_sock.version()

                cert = tls_sock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                common_name = subject.get("commonName", "Unknown")

                # Attempt HTTP request over TLS for better fingerprinting
                try:
                    tls_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " +
                                     target_ip.encode() + b"\r\n\r\n")
                    response = tls_sock.recv(1024)
                    decoded = response.decode("utf-8", errors="ignore")
                    service = identify_by_signature(decoded)
                except Exception:
                    service = "TLS Service"

                return f"[{service}] TLS:{tls_version} CN:{common_name}"

    except Exception:
        return None


def identify_by_signature(banner_text):
    """
    Matches banner text against predefined regex signatures.

    Returns:
        Identified service name if match found.
        'Unknown Service' otherwise.
    """
    for service, pattern in SIGNATURES.items():
        if re.search(pattern, banner_text, re.IGNORECASE):
            return service
    return "Unknown Service"


def discover_service(target_ip: str, port: int) -> str:
    """
    Performs service detection on an open TCP port.

    Detection Strategy:
        1. If port is TLS-associated, attempt TLS handshake.
        2. If TLS fails or not applicable, use plain TCP.
        3. Attempt passive banner read.
        4. If no banner, send protocol-aware probe.
        5. Apply signature classification to response.

    Returns:
        Formatted service identification string.
    """

    # ---- Try TLS First (if common TLS port) ----
    if port in TLS_PORTS:
        tls_result = try_tls(target_ip, port)
        if tls_result:
            return tls_result

    # ---- Fallback to Plain TCP ----
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2.5)

        try:
            s.connect((target_ip, port))
            banner_data = None

            # Attempt passive banner grab
            try:
                banner_data = s.recv(1024)
            except (socket.timeout, ConnectionResetError):
                pass

            # If no passive banner, try protocol-specific probe
            if not banner_data:
                if port in PROBE_MAP:
                    try:
                        s.sendall(PROBE_MAP[port])
                        banner_data = s.recv(1024)
                    except (socket.timeout, ConnectionResetError):
                        banner_data = None

            # Final fallback: generic newline probe
            if not banner_data:
                try:
                    s.sendall(b"\r\n\r\n")
                    banner_data = s.recv(1024)
                except (socket.timeout, ConnectionResetError):
                    return "Open Port: Silent (No response to any probe)"

            if banner_data:
                decoded = banner_data.decode('utf-8', errors='ignore').strip()
                service_type = identify_by_signature(decoded)
                return f"[{service_type}] {decoded}"

        except (ConnectionRefusedError, socket.timeout):
            return "Connection Failed"
        except Exception as e:
            return f"Error: {str(e)}"

    return "Unknown State"
