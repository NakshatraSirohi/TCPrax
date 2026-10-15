"""
TCPrax Entry Point / Dispatcher

Thin dispatcher between the two presentation layers:

    main() ── --gui ──> run_gui()   (lazy import; PySide6 required)
           └─ otherwise ─> run_cli()

The CLI is the adapter that turns parsed arguments into a shared
ScanConfiguration and drives the application layer (scan_controller),
then formats and saves results with the report package. All scanning and
service-detection logic lives in the core/service modules behind the
application API - never here, and never duplicated for the GUI.
"""

import os
import sys

# Resolve the bundled packages (application, core, service, ...) from this
# file's own directory rather than from the current working directory, so
# TCPrax runs identically however it is launched (`python3 /any/path/main.py`
# from any cwd, through a symlink, `runpy`, or `python3 -m main`).
_ROOT = os.path.dirname(os.path.realpath(__file__))
if os.path.realpath(sys.path[0] or os.curdir) != _ROOT:
    sys.path.insert(0, _ROOT)

from application.events import (EventType, ScanConfigurationError,  # noqa: E402
                                TargetResolutionError, TCPraxError)
from application.scan_configuration import ScanConfiguration  # noqa: E402
from application.scan_controller import run_scan  # noqa: E402
from cli import parse_arguments  # noqa: E402
from report.formatter import (format_metrics, format_results,  # noqa: E402
                              format_summary, format_text_report)
from report.writer import (ReportWriteError, validate_output_path,  # noqa: E402
                           write_report)


def run_cli(argv: "list[str] | None" = None) -> int:
    """
    CLI adapter: parse arguments, build a ScanConfiguration, run it
    through the application API, and present/save the report.

    Returns:
        Process exit code (0 ok, 1 output write failure, 2 usage/config).
    """
    args = parse_arguments(argv)

    # CLI-specific scan-mode rules (the GUI always sets exactly one).
    if args.sT and args.sS:
        print("Error: Choose only one scan type (-sT or -sS).",
              file=sys.stderr)
        return 2
    if not args.sT and not args.sS:
        print("Error: Specify a scan type (-sT or -sS).", file=sys.stderr)
        return 2

    config = ScanConfiguration.from_namespace(args)
    try:
        config.validate()
    except ScanConfigurationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # Fail fast on an unusable output path, before a potentially long scan.
    if config.output_path is not None:
        try:
            validate_output_path(config.output_path)
        except ReportWriteError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    # Print the configuration summary as soon as the scan starts (after
    # target resolution), matching the previous CLI output ordering.
    def listener(event) -> None:
        if event.type == EventType.SCAN_STARTED:
            print("\n".join(format_summary(event.data["meta"])))

    try:
        report = run_scan(config, on_event=listener)
    except (ScanConfigurationError, TargetResolutionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except TCPraxError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # ---- Results and metrics ----
    for line in format_results(report.results, config.service_detection):
        print(line)
    print("\n".join(format_metrics(report.metrics)))

    # ---- Optional report file ----
    if config.output_path is not None:
        try:
            write_report(config.output_path,
                         format_text_report(report.meta, report.results,
                                            report.metrics))
        except ReportWriteError as exc:
            print(f"\nError: {exc}", file=sys.stderr)
            return 1
        print(f"\nReport saved to: {config.output_path}")

    return 0


def run_gui(argv: "list[str] | None" = None) -> int:
    """
    Launches the PySide6/QML GUI (lazy-imported so CLI startup stays
    lightweight and does not require PySide6).

    Returns:
        Process exit code. If PySide6 is not installed, prints a clear
        installation message and returns non-zero rather than crashing
        with an obscure import error.
    """
    try:
        from gui.app import run_gui as _run_gui
    except ImportError as exc:
        if "PySide6" in str(exc) or "shiboken" in str(exc):
            print("Error: the GUI requires PySide6, which is not installed.\n"
                  "Install it with:  pip install PySide6\n"
                  "The CLI works without it.", file=sys.stderr)
        else:
            print(f"Error: the GUI could not be loaded: {exc}",
                  file=sys.stderr)
        return 3
    return _run_gui(argv)


def main(argv: "list[str] | None" = None) -> int:
    """
    Dispatches to the GUI or the CLI.

    Rules:
        --gui                       -> GUI mode
        no arguments at all         -> GUI mode (convenience)
        anything else (CLI options) -> CLI mode
    """
    args = sys.argv[1:] if argv is None else argv

    if "--gui" in args:
        remaining = [a for a in args if a != "--gui"]
        return run_gui(remaining)

    # Bare `main.py` with no arguments launches the GUI for convenience;
    # any CLI arguments mean CLI mode.
    if not args:
        return run_gui([])

    # An explicit --cli flag is accepted and simply stripped.
    if "--cli" in args:
        args = [a for a in args if a != "--cli"]

    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
