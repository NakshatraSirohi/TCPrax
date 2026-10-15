"""
TCPrax Scan Core

Connect and raw SYN scan engines plus their supporting pieces (packet
build/parse, port-state classification, RTT/timeout estimation, retries,
scheduling, source-port allocation). Driven only via the application
layer.

A regular package (not a namespace package) so an unrelated `core`
package elsewhere on sys.path can never take precedence over this one.
"""
