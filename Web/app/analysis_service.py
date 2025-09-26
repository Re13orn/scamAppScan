"""Backend utilities powering the lightweight HTTP server.

The original project relied on Flask and several third-party dependencies that
are unavailable in the execution environment.  This module extracts the core
logic for handling uploads and running the APK analysis so that it can be
re-used by a minimal standard-library server implementation.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import md5
from pathlib import Path
from typing import Dict, Iterable, Optional

from app.utils.apkAnalyzer import APKAnalyzer
from app.utils.apkShellDetector import APKShellDetector
from app.utils.scamAppScanConfig import (
    DOMAIN_PATTERNS,
    HASH_PATTERNS,
    PATH_PATTERNS,
    SHELLFEATURE,
    TEMP_DIRECTORY,
)


LOGGER = logging.getLogger(__name__)


@dataclass
class UploadPayload:
    """Represents the JSON payload returned after a successful upload."""

    analyzer: str
    status: str
    status_code: int
    hash: str
    scan_type: str
    file_name: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "analyzer": self.analyzer,
            "status": self.status,
            "status_code": self.status_code,
            "hash": self.hash,
            "scan_type": self.scan_type,
            "file_name": self.file_name,
        }


class AnalysisService:
    """Coordinate APK uploads and analysis using only the standard library."""

    def __init__(self, config, executor: Optional[ThreadPoolExecutor] = None) -> None:
        self.config = config
        self.upload_root = Path(config.UPLOAD_FOLDER)
        self.apk_dir = Path(config.UPLOAD_FOLDER_APK)
        self.json_dir = Path(config.UPLOAD_FOLDER_JSON)
        self.tmp_dir = Path(config.UPLOAD_FOLDER_TMP)
        self.executor = executor or ThreadPoolExecutor(max_workers=4)

        for directory in (self.upload_root, self.apk_dir, self.json_dir, self.tmp_dir):
            directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Upload handling
    # ------------------------------------------------------------------
    def allowed_file(self, filename: str) -> bool:
        return "." in filename and filename.rsplit(".", 1)[1].lower() in {"apk", "apks", "xapk"}

    def compute_hash(self, file_path: Path) -> str:
        digest = md5()
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(4096), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def finalize_apk(self, file_path: Path, original_filename: str) -> UploadPayload:
        file_hash = self.compute_hash(file_path)
        destination = self.apk_dir / f"{file_hash}.apk"
        os.replace(file_path, destination)
        return UploadPayload(
            analyzer="api/submitrunscan",
            status="success",
            status_code=200,
            hash=file_hash,
            scan_type="apk",
            file_name=original_filename,
        )

    def handle_chunk(
        self,
        *,
        upload_id: str,
        file_name: str,
        chunk_index: int,
        total_chunks: int,
        file_size: int,
        chunk_data: bytes,
    ) -> Dict[str, object]:
        if not self.allowed_file(file_name):
            return {"error": "File type not supported", "status_code": 400}

        tmp_path = self.tmp_dir / f"{upload_id}.part"

        if chunk_index == 0 and tmp_path.exists():
            tmp_path.unlink()

        try:
            with open(tmp_path, "ab") as destination:
                destination.write(chunk_data)
        except Exception as exc:  # pragma: no cover - defensive
            if tmp_path.exists():
                tmp_path.unlink()
            return {"error": f"Failed to write chunk: {exc}", "status_code": 500}

        is_last_chunk = chunk_index + 1 == total_chunks
        if not is_last_chunk:
            written = tmp_path.stat().st_size
            return {
                "status": "continue",
                "status_code": 202,
                "received_bytes": written,
                "total_bytes": file_size,
            }

        if tmp_path.stat().st_size != file_size:
            tmp_path.unlink(missing_ok=True)
            return {"error": "Uploaded size does not match file size", "status_code": 400}

        final_name = Path(file_name).name
        final_path = self.apk_dir / final_name
        try:
            shutil.move(tmp_path, final_path)
            payload = self.finalize_apk(final_path, final_name)
            return payload.to_dict()
        except Exception as exc:  # pragma: no cover - defensive
            tmp_path.unlink(missing_ok=True)
            final_path.unlink(missing_ok=True)
            return {"error": f"Failed to finalise upload: {exc}", "status_code": 500}

    # ------------------------------------------------------------------
    # Analysis pipeline
    # ------------------------------------------------------------------
    def start_analysis(self, apk_hash_filename: str) -> Dict[str, object]:
        self.executor.submit(self.run_analysis, apk_hash_filename, True)
        return {
            "status": "success",
            "status_code": 200,
            "message": "Analysis started! Please wait or check recent scans after sometime.",
            "hash": apk_hash_filename,
        }

    def run_analysis(self, apk_hash_filename: str, check_cache: bool) -> None:
        json_filename = self.json_dir / f"{apk_hash_filename}.json"
        if check_cache and json_filename.exists():
            return

        apk_file = self.apk_dir / f"{apk_hash_filename}.apk"
        shell = "unknown"
        try:
            detector = APKShellDetector(str(apk_file), SHELLFEATURE)
            detected = detector.detect()
            if detected:
                shell = detected
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Shell detection failed for %s: %s", apk_hash_filename, exc)

        combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
        results = []
        status_code = 500
        is_scam_app = "unknown"
        rule_miss = False

        try:
            analyzer = APKAnalyzer(str(apk_file), TEMP_DIRECTORY)
            results = analyzer.analyze_apk(combined_patterns)
            has_matches = any(entry.get("match_rule") for entry in results)
            status_code = 200
            is_scam_app = "true" if has_matches else "false"
            rule_miss = not has_matches
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("run_analysis error for %s: %s", apk_hash_filename, exc)
            status_code = 500

        history = self.history_apk_hash_compare(apk_hash_filename)

        payload = {
            "status_code": status_code,
            "isScamApp": is_scam_app,
            "result": json.dumps(results, ensure_ascii=False, indent=4),
            "history": history,
            "shell": shell,
            "rule_miss": rule_miss,
        }

        with open(json_filename, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=4)

    def history_apk_hash_compare(self, apk_hash: str) -> Iterable[Iterable[str]]:
        history = []
        for known_hash, domain in HASH_PATTERNS.items():
            if apk_hash == known_hash:
                history.append((known_hash, domain))
        return history

    def get_scan_result(self, apk_hash_filename: str) -> Dict[str, object]:
        json_path = self.json_dir / f"{apk_hash_filename}.json"
        if json_path.exists():
            with open(json_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {
            "status_code": 404,
            "message": "Analyzing, please wait.",
        }

    def refresh_results(self) -> Dict[str, object]:
        json_files = [path for path in self.json_dir.glob("*.json")]
        refreshed = 0
        for json_file in json_files:
            with open(json_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            status = data.get("isScamApp", "").lower()
            if status in {"unknown", "unknow"}:
                apk_hash_filename = json_file.stem
                self.executor.submit(self.run_analysis, apk_hash_filename, False)
                refreshed += 1

        return {
            "status": "success",
            "status_code": 200,
            "message": "Analysis started! Please wait or check recent scans after sometime.",
            "refreshed": refreshed,
        }


__all__ = ["AnalysisService", "UploadPayload"]

