# TCPrax

TCPrax is a Python-based TCP reconnaissance tool that performs:

* TCP Connect Scan
* TCP Half-Open (SYN) Scan
* Open Port Detection
* Basic Banner Grabbing

The project demonstrates low-level socket handling, TCP flag control, and manual service enumeration.

---

## Features

* Full TCP connect scanning
* Stealth-oriented SYN half-open scanning
* Open port identification
* Service banner extraction
* Minimal external dependencies

---

## Requirements

* Python 3.9+
* Linux (SYN scan requires raw socket permissions)
* Root privileges for half-open scan

