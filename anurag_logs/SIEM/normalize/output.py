"""
normalize/output.py
===================
Output module - writes normalized JSON events.

Supports three output modes:
  1. FILE   - append to a .jsonl file (one JSON per line)
  2. STDOUT - print to console (useful for piping to other tools)
  3. LIST   - collect into a Python list (useful for testing / in-memory use)

Your teammate receives the .jsonl file as the handoff artifact.
JSONL (JSON Lines) format = one complete JSON object per line.
This is the industry standard for log pipelines (used by Elasticsearch,
Splunk HEC, Kafka producers, etc.)
"""

import json
import sys
from typing import Optional


class OutputWriter:
    """
    Writes normalized log events to one or more destinations.
    """

    def __init__(self, output_file: Optional[str] = "normalized_logs.jsonl",
                 stdout: bool = False):
        """
        Args:
            output_file: Path to write .jsonl output. Set to None to skip file output.
            stdout:      If True, also print each event to stdout.
        """
        self.output_file = output_file
        self.stdout = stdout
        self._count = 0
        self._file_handle = None

        if output_file:
            self._file_handle = open(output_file, "w", encoding="utf-8")

    def write(self, normalized_event: dict) -> None:
        """Write one normalized event."""
        line = json.dumps(normalized_event, ensure_ascii=False, default=str)
        if self._file_handle:
            self._file_handle.write(line + "\n")
        if self.stdout:
            print(line)
        self._count += 1

    def write_all(self, events: list) -> None:
        """Write a list of normalized events."""
        for event in events:
            self.write(event)

    def close(self) -> None:
        """Flush and close the file handle."""
        if self._file_handle:
            self._file_handle.flush()
            self._file_handle.close()
            self._file_handle = None

    @property
    def count(self) -> int:
        """Number of events written so far."""
        return self._count

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
