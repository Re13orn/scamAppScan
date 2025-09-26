"""Lightweight APK analysis utilities used by the offline web server.

This module intentionally avoids third-party dependencies so that it can run
inside the execution environment where installing packages such as
``androguard`` or ``loguru`` is not possible.  The implementation focuses on
string pattern matching within the ZIP archive that makes up an APK file.
"""

from __future__ import annotations

import io
import logging
import os
import zipfile
from hashlib import md5
from pathlib import Path
from typing import Dict, Iterable, List


logger = logging.getLogger(__name__)


class APKAnalyzer:
    """Perform best-effort static analysis on an APK archive.

    The analyzer scans every file in the APK ZIP archive, decoding textual
    content and searching for the configured patterns.  While this is less
    accurate than using specialised tools, it provides useful signal without
    relying on external dependencies that are unavailable in the sandbox.
    """

    #: Number of bytes to read from each archived file when scanning.  Large
    #: assets such as images are skipped after this limit to keep resource
    #: usage predictable.
    MAX_SCAN_BYTES = 2 * 1024 * 1024  # 2 MiB

    def __init__(self, apk_path: str, temp_directory: str | os.PathLike[str]):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.temp_directory = Path(temp_directory)
        # Ensure the temporary directory exists for compatibility with earlier
        # behaviour that expected it to be present.
        self.temp_directory.mkdir(parents=True, exist_ok=True)

    def analyze_apk(self, patterns: Dict[str, int]) -> List[Dict[str, object]]:
        """Inspect the APK and collect pattern matches.

        Parameters
        ----------
        patterns:
            Mapping of suspicious substrings to their accuracy score.

        Returns
        -------
        list of dict
            Each entry contains the match metadata combined with basic APK
            information so that callers can serialise the result directly.
        """

        apk_hash = self.calculate_hash()
        apk_info = {
            "apk_name": self.apk_name,
            "app_version": "unknown",
            "hash": apk_hash,
            "Package_name": os.path.splitext(self.apk_name)[0],
            "app_name": os.path.splitext(self.apk_name)[0],
        }

        matches: List[Dict[str, object]] = []

        try:
            with zipfile.ZipFile(self.apk_path, "r") as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue

                    try:
                        with archive.open(member.filename, "r") as file_obj:
                            text = self._read_member(file_obj)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "Failed to read %s from %s: %s",
                            member.filename,
                            self.apk_name,
                            exc,
                        )
                        continue

                    for match in self.analyze_content(text, patterns):
                        result = {**match, **apk_info, "source_file": member.filename}
                        matches.append(result)

        except zipfile.BadZipFile as exc:
            logger.error("Failed to open %s: %s", self.apk_path, exc)

        # Always return at least one row with the APK metadata so the caller
        # can populate the summary panel even when no patterns matched.
        if not matches:
            matches.append({**apk_info})

        return matches

    def analyze_content(self, content: str, patterns: Dict[str, int]) -> Iterable[Dict[str, object]]:
        """Find pattern matches within *content* and yield context snippets."""

        context_padding = 120
        for pattern, accuracy in patterns.items():
            start = 0
            while True:
                index = content.find(pattern, start)
                if index == -1:
                    break
                context_start = max(0, index - context_padding)
                context_end = min(len(content), index + len(pattern) + context_padding)
                snippet = content[context_start:context_end]
                yield {
                    "match_rule": pattern,
                    "match_value": snippet,
                    "accuracy": accuracy,
                }
                start = index + len(pattern)

    def _read_member(self, file_obj: io.BufferedReader) -> str:
        """Decode a ZIP member to text, truncating very large files."""

        data = file_obj.read(self.MAX_SCAN_BYTES)
        if not data:
            return ""
        return data.decode("utf-8", errors="ignore")

    def calculate_hash(self) -> str:
        """Compute the MD5 hash of the APK for consistent filenames."""

        digest = md5()
        with open(self.apk_path, "rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(4096), b""):
                digest.update(chunk)
        return digest.hexdigest()


__all__ = ["APKAnalyzer"]

