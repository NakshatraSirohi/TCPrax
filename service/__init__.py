"""
TCPrax Service Detection

Banner grabbing (with TLS awareness), the fingerprint engine and its
bundled datasets (TCPrax, Nmap-derived and IANA-based common services).

A regular package (not a namespace package) so an unrelated `service`
package elsewhere on sys.path can never take precedence over this one.
"""
