"""
Report Writer Module

Handles persisting formatted scan reports to disk.

Responsibilities:
- Validate the requested output path before a scan starts
- Write report content to the output file
- Convert low-level I/O failures into a single clean exception type

This module performs no formatting and no scanning.
"""

import os


class ReportWriteError(Exception):
    """Raised when a report cannot be written to the requested path."""


def validate_output_path(path: str) -> None:
    """
    Checks that a report can be written to the given path.

    Performed before scanning so that an unusable path is reported
    immediately instead of after a potentially long scan. The file
    itself is not created here.

    Raises:
        ReportWriteError if the path is empty, is a directory, its
        parent directory does not exist, or it is not writable.
    """

    if not path or not path.strip():
        raise ReportWriteError("Output file path is empty.")

    if os.path.isdir(path):
        raise ReportWriteError(f"Output path '{path}' is a directory.")

    parent = os.path.dirname(os.path.abspath(path))

    if not os.path.isdir(parent):
        raise ReportWriteError(
            f"Output directory '{parent}' does not exist.")

    if os.path.exists(path):
        if not os.access(path, os.W_OK):
            raise ReportWriteError(
                f"Output file '{path}' is not writable (permission denied).")
    elif not os.access(parent, os.W_OK | os.X_OK):
        raise ReportWriteError(
            f"Cannot create '{path}' in '{parent}' (permission denied).")


def write_report(path: str, content: str) -> None:
    """
    Writes report content to the given path (UTF-8), replacing any
    existing file.

    Raises:
        ReportWriteError on any I/O failure.
    """
    try:
        with open(path, "w", encoding="utf-8") as report_file:
            report_file.write(content)
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise ReportWriteError(
            f"Could not write report to '{path}': {reason}") from exc
