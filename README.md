# TCPrax

TCPrax is a modular TCP reconnaissance scanner written in Python: TCP
Connect and raw SYN half-open scans, multithreaded scanning with adaptive
RTT-driven timeouts, service/version detection with TLS awareness, and
text reports — driven by a command-line interface or an optional desktop
GUI that share one scanning engine.

This directory is the standalone runtime distribution: it contains only
what is needed to run TCPrax.

## Requirements

- **Python 3.10+**
- **CLI:** standard library only — nothing to install.
- **GUI (optional):** `PySide6 >= 6.5` — `pip install -r requirements-gui.txt`
- **SYN scan (`-sS`):** root / `CAP_NET_RAW` (Linux), plus external
  kernel-RST suppression to keep half-open semantics.

## Running

TCPrax locates its own packages relative to `main.py`, so it can be run
from any working directory:

```bash
python3 /path/to/TCPrax/main.py --help
```

### CLI

```bash
python3 main.py <host> (-p PORTS | --top-ports N) (-sT | -sS) [options]

# Connect scan of specific ports, 50 threads
python3 main.py 192.168.1.1 -p 22,80,443 -sT -t 50

# SYN scan of the 100 most common ports, with retries, saved to a file
sudo python3 main.py example.com -sS --top-ports 100 --retries 3 -o scan.txt

# Connect scan with service/version detection
python3 main.py example.com -p 1-1000 -sT -sV
```

| Option | Description |
| --- | --- |
| `host` | Target host (IPv4 address or domain) — required |
| `-p`, `--ports PORTS` | Ports: `80`, `1-1000`, `22,80,443`, `1-20,40-75` |
| `--top-ports N` | Scan the N most common TCP ports (1–1000) |
| `-sT` | TCP Connect scan |
| `-sS` | TCP SYN scan (requires root) |
| `-sV` | Service/version detection |
| `-t`, `--threads N` | Concurrent threads (1–300); default is adaptive |
| `-o`, `--output FILE` | Save the full report to a plain-text file (relative paths resolve against the current directory) |
| `--retries N` | Extra probes for FILTERED/OTHER ports (default 0) |

Exactly one of `-p/--ports` or `--top-ports`, and exactly one of `-sT` or
`-sS`, is required. Exit codes: `0` success, `1` report-write failure,
`2` usage/configuration error, `3` GUI requested but PySide6 missing.

### GUI

```bash
pip install -r requirements-gui.txt
python3 main.py --gui        # explicit
python3 main.py              # no arguments also launches the GUI
```

Any scan arguments select the CLI; `--cli` is accepted and ignored.

## Limitations

IPv4 and TCP only; SYN scanning is Linux-only and needs root; no OS
fingerprinting.

## License

MIT License (see `LICENSE`), Copyright (c) 2026 Nakshatra Sirohi.
Bundled third-party data (a curated subset of Nmap's
`nmap-service-probes` under the NPSL, and IANA service/port
registrations) is credited in `NOTICE`.

## Disclaimer

TCPrax is for authorized security testing, research and education only.
Scan only systems you own or have explicit permission to test.
