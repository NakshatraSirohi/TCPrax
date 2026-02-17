import socket
import errno
import time
import sys

host = input("Enter host: ")
start_port = int(input("Start port: "))
end_port = int(input("End port: "))

try:
    target_ip = socket.gethostbyname(host)
except socket.gaierror:
    print("Hostname could not be resolved.")
    sys.exit()

# ==== Calculating RTT ====
print(f"\nCalibrating RTT for {host}")

calibration_ports = [80, 443, 22]
rtt_samples = []


def is_port_open(port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(2)

    result = tcp_sock.connect_ex((target_ip, port))
    tcp_sock.close()

    return (result == 0)


def each_port_rtt(port):
    for _ in range(0, 5):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(2)

        start_rtt = time.perf_counter()
        result = tcp_sock.connect_ex((target_ip, port))
        end_rtt = time.perf_counter()
        tcp_sock.close()

        if result == 0:
            rtt = end_rtt - start_rtt
            rtt_samples.append(rtt)


for port in calibration_ports:
    if (is_port_open(port)):
        each_port_rtt(port)
    else:
        continue

if rtt_samples:
    rtt_samples.sort()
    median_rtt = rtt_samples[len(rtt_samples) // 2]
    timeout = median_rtt * 3
else:
    timeout = 1.0

timeout = max(0.5, min(timeout, 5))

print(f"Using timeout: {timeout:.2f} seconds\n")

#===== Scanning Ports =====
for port in range(start_port, end_port + 1):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(timeout)
    result = tcp_sock.connect_ex((target_ip, port))

    if result == 0:
        print(f"{port:5d} | OPEN")
    elif result == errno.ECONNREFUSED:
        print(f"{port:5d} | CLOSED")
    elif result == errno.ETIMEDOUT:
        print(f"{port:5d} | FILTERED")
    else:
        print(f"{port:5d} | OTHER")

    tcp_sock.close()

print("\nScan Complete.")
