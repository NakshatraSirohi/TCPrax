"""
TCPrax-Native Service Fingerprints (MIT)

Hand-authored fingerprints for common services, tuned to match the
banners those services actually emit and to extract product/version
where the banner provides it. These are TCPrax's own signatures
(source="tcprax"); they include and extend the original SIGNATURES from
banner.py so existing detection is preserved.

They are given lower priority numbers than the Nmap-derived set, so for
common services TCPrax's own, well-tested patterns win, while the
Nmap-derived fingerprints add breadth for the long tail.

Priority convention (lower runs first):
    10  exact product + version
    15  exact product
    30  generic service (no product/version)
"""

import re

from .fingerprints import ServiceFingerprint, SOURCE_TCPRAX
from .result import CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM


def _fp(service, pattern, priority, *, flags=0, product=None, version=None,
        info=None, confidence=CONFIDENCE_MEDIUM, name=None):
    return ServiceFingerprint(service=service, pattern=pattern, flags=flags,
                              product=product, version=version, info=info,
                              confidence=confidence, priority=priority,
                              source=SOURCE_TCPRAX, name=name)


TCPRAX_FINGERPRINTS = [
    # ---- SSH ----
    _fp("ssh", rb"^SSH-[\d.]+-OpenSSH[_-]([\w.]+)", 10, product="OpenSSH",
        version="$1", info="protocol", confidence=CONFIDENCE_HIGH),
    _fp("ssh", rb"^SSH-([\d.]+)-([^\r\n ]+)", 30, info="protocol $1",
        confidence=CONFIDENCE_MEDIUM),

    # ---- HTTP (Server header products) ----
    _fp("http", rb"Server: nginx/([\d.]+)", 10, product="nginx",
        version="$1", flags=re.IGNORECASE, confidence=CONFIDENCE_HIGH),
    _fp("http", rb"Server: nginx", 15, product="nginx", flags=re.IGNORECASE),
    _fp("http", rb"Server: Apache/([\d.]+)", 10, product="Apache httpd",
        version="$1", flags=re.IGNORECASE, confidence=CONFIDENCE_HIGH),
    _fp("http", rb"Server: Apache", 15, product="Apache httpd",
        flags=re.IGNORECASE),
    _fp("http", rb"Server: Microsoft-IIS/([\d.]+)", 10,
        product="Microsoft IIS", version="$1", flags=re.IGNORECASE,
        confidence=CONFIDENCE_HIGH),
    _fp("http", rb"Server: ([^\r\n]+)", 25, product="$1",
        flags=re.IGNORECASE, confidence=CONFIDENCE_MEDIUM),
    _fp("http", rb"^HTTP/\d\.\d \d\d\d", 30, info="HTTP response",
        confidence=CONFIDENCE_LOW),
    _fp("http", rb"<html", 35, flags=re.IGNORECASE, confidence=CONFIDENCE_LOW),

    # ---- FTP ----
    _fp("ftp", rb"^220[- ].*vsFTPd ([\d.]+)", 10, product="vsftpd",
        version="$1", confidence=CONFIDENCE_HIGH),
    _fp("ftp", rb"^220[- ].*ProFTPD ([\d.]+)", 10, product="ProFTPD",
        version="$1", confidence=CONFIDENCE_HIGH),
    _fp("ftp", rb"^220[- ].*FileZilla Server", 15, product="FileZilla Server"),
    _fp("ftp", rb"^220[- ].*(?:FTP|FileZilla|Pure-FTPd)", 30,
        info="FTP banner", confidence=CONFIDENCE_LOW),

    # ---- SMTP ----
    _fp("smtp", rb"^220[- ].*Postfix", 15, product="Postfix"),
    _fp("smtp", rb"^220[- ].*Exim ([\d.]+)", 10, product="Exim",
        version="$1", confidence=CONFIDENCE_HIGH),
    _fp("smtp", rb"^220[- ].*(?:SMTP|ESMTP)", 30, info="SMTP banner",
        confidence=CONFIDENCE_LOW),

    # ---- POP3 / IMAP ----
    _fp("pop3", rb"^\+OK.*(?:POP3|Dovecot)", 30, info="POP3 banner",
        flags=re.IGNORECASE, confidence=CONFIDENCE_LOW),
    _fp("imap", rb"^\* OK.*IMAP", 30, info="IMAP banner",
        flags=re.IGNORECASE, confidence=CONFIDENCE_LOW),

    # ---- Databases ----
    _fp("mysql", rb"([\d.]+)-MariaDB", 10, product="MariaDB", version="$1",
        confidence=CONFIDENCE_HIGH),
    _fp("mysql", rb"mysql_native_password", 20, product="MySQL"),
    _fp("mysql", rb"\x00\x00\x00\x0a([\w.\-]+)\x00", 20, product="MySQL",
        version="$1"),
    _fp("postgresql", rb"^E\x00\x00\x00.*(?:FATAL|PostgreSQL)", 30,
        info="PostgreSQL", confidence=CONFIDENCE_LOW),
    _fp("postgresql", rb"PostgreSQL", 25, product="PostgreSQL"),
    _fp("redis", rb"redis_version:([\d.]+)", 10, product="Redis",
        version="$1", confidence=CONFIDENCE_HIGH),
    _fp("redis", rb"\+PONG", 30, info="Redis", confidence=CONFIDENCE_LOW),
    _fp("mongodb", rb"MongoDB", 20, product="MongoDB"),

    # ---- Remote / graphical ----
    _fp("vnc", rb"^RFB (\d{3}\.\d{3})", 15, product="VNC",
        info="protocol $1"),
    _fp("telnet", rb"^\xff[\xfb-\xfe]", 30, info="Telnet negotiation",
        confidence=CONFIDENCE_LOW),

    # ---- Windows file sharing (SMB1/SMB2) ----
    _fp("smb", rb"\xffSMB", 20, product="SMB"),
    _fp("smb", rb"\xfeSMB", 20, product="SMB2"),
]


# Minimal port -> candidate services hints (expanded by the 256-service
# dataset). Used ONLY to prioritise probes and narrow candidate
# fingerprints, never as proof of a service.
PORT_SERVICE_HINTS = {
    21: ("ftp",), 22: ("ssh",), 23: ("telnet",), 25: ("smtp",),
    53: ("domain",), 80: ("http",), 110: ("pop3",), 143: ("imap",),
    443: ("http", "ssl"), 465: ("smtp",), 587: ("smtp",), 993: ("imap",),
    995: ("pop3",), 1433: ("ms-sql-s",), 3306: ("mysql",),
    3389: ("ms-wbt-server",), 5432: ("postgresql",), 5900: ("vnc",),
    6379: ("redis",), 8080: ("http",), 8443: ("http", "ssl"),
    27017: ("mongodb",),
}
