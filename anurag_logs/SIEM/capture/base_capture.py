"""
capture/base_capture.py
=======================
Abstract base class for all log capture parsers.

LEARNING NOTE:
--------------
Every log parser follows the same contract:
  - Input : a raw log line (str) — exactly as received from the source
  - Output: a Python dict of extracted fields — ready for the normalizer

This consistent interface means the normalizer does not care which parser
produced the dict; it just maps fields to the common schema.
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseCapture(ABC):
    """
    Abstract base class for all 12 log type parsers.
    Subclass this and implement LOG_TYPE and parse().
    """

    # Each subclass must set this to one of the 12 log type identifiers
    LOG_TYPE: str = "unknown"

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single raw log line and return extracted fields.

        Args:
            raw_line: The raw log string exactly as received.

        Returns:
            A dict of extracted fields, or None if unparseable.

        Common keys to return (all optional except raw):
            raw         : str  -- always include the original line
            timestamp   : str  -- original timestamp string
            source_ip   : str
            dest_ip     : str
            source_port : int
            dest_port   : int
            protocol    : str  -- "TCP", "UDP", "ICMP", etc.
            action      : str  -- "allow", "block", "detect", etc.
            user        : str
            hostname    : str
            event_id    : str
            severity    : str  -- "low", "medium", "high", "critical"
            message     : str  -- human-readable description
            extra       : dict -- log-type-specific fields
        """
        pass

    def parse_lines(self, raw_text: str) -> list:
        """
        Parse multiple lines at once. Skips None results.

        Args:
            raw_text: Multi-line string (e.g., full log file contents).

        Returns:
            List of extracted-field dicts.
        """
        results = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            result = self.parse(line)
            if result is not None:
                results.append(result)
        return results
