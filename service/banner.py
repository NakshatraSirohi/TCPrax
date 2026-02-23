import socket
import re

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


def identify_by_signature(banner_text):
    for service, pattern in SIGNATURES.items():
        if re.search(pattern, banner_text, re.IGNORECASE):
            return service
    return "Unknown Service"


def discover_service(target_ip: str, port: int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2.5)

        try:
            s.connect((target_ip, port))
            banner_data = None

            try:
                banner_data = s.recv(1024)
            except (socket.timeout, ConnectionResetError):
                pass

            if not banner_data:
                if port in PROBE_MAP:
                    try:
                        s.sendall(PROBE_MAP[port])
                        banner_data = s.recv(1024)
                    except (socket.timeout, ConnectionResetError):
                        banner_data = None

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
