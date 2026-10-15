"""
TCPrax Application Layer

The application layer sits between the presentation layers (CLI, GUI) and
the scan core. It owns:

- the shared ScanConfiguration model (one config for both interfaces),
- input validation/parsing reused by both interfaces,
- the scan controller (orchestration) and its progress/cancel events.

Neither the CLI nor the GUI implements scanning; both build a
ScanConfiguration and drive it through this layer, which calls the core.
This module must not import any presentation layer (cli or gui).
"""
