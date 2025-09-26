"""A minimal HTTP server that exposes the Scam App Scan web interface.

The original project depends on Flask, but the execution environment does not
allow installing additional packages.  This module provides a compact
implementation based on :mod:`http.server` so the UI can be demonstrated and
tested end-to-end.
"""

from __future__ import annotations

import cgi
import io
import json
import logging
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlparse

from config import Config
from app.analysis_service import AnalysisService


LOGGER = logging.getLogger(__name__)


class ScamAppHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ScamAppScan/0.1"

    service: ClassVar[AnalysisService] = AnalysisService(Config)
    base_dir: ClassVar[Path] = Path(__file__).parent
    template_path: ClassVar[Path] = base_dir / "app" / "templates" / "index.html"
    static_dir: ClassVar[Path] = base_dir / "app" / "static"
    fixture_dir: ClassVar[Path] = base_dir.parent / "apkStore"

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._serve_file(self.template_path)
            return

        if parsed.path.startswith("/static/"):
            relative = parsed.path.removeprefix("/static/")
            file_path = self.static_dir / relative
            self._serve_file(file_path)
            return

        if parsed.path.startswith("/fixtures/"):
            filename = parsed.path.removeprefix("/fixtures/")
            file_path = self.fixture_dir / filename
            self._serve_file(file_path)
            return

        if parsed.path.startswith("/api/submitrunscan/"):
            apk_hash = parsed.path.rstrip("/").split("/")[-1]
            payload = self.service.start_analysis(apk_hash)
            self._send_json(payload)
            return

        if parsed.path.startswith("/api/getscanresult/"):
            apk_hash = parsed.path.rstrip("/").split("/")[-1]
            payload = self.service.get_scan_result(apk_hash)
            self._send_json(payload)
            return

        if parsed.path == "/api/refreshresult/":
            payload = self.service.refresh_results()
            self._send_json(payload)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in {"/api/upload", "/api/upload-chunk"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        content_length = int(self.headers.get("Content-Length", "0") or 0)
        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(content_length)

        form = cgi.FieldStorage(
            fp=io.BytesIO(body),
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
                "CONTENT_LENGTH": str(content_length),
            },
            keep_blank_values=True,
        )

        if parsed.path == "/api/upload":
            response = self._handle_upload(form)
        else:
            response = self._handle_chunked_upload(form)

        status = HTTPStatus.OK if response.get("status") in {"success", "continue"} else HTTPStatus.BAD_REQUEST
        if "error" in response or response.get("status_code") in {500}:
            status = HTTPStatus.INTERNAL_SERVER_ERROR if response.get("status_code") == 500 else HTTPStatus.BAD_REQUEST

        self._send_json(response, status=status)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _handle_upload(self, form: cgi.FieldStorage) -> dict:
        file_field = form.getfirst("file")
        if not isinstance(file_field, (bytes, str)):
            return {"error": "Upload requires a file", "status_code": 400}
        return {"error": "Direct uploads are not supported in offline mode", "status_code": 400}

    def _handle_chunked_upload(self, form: cgi.FieldStorage) -> dict:
        chunk_field = form["chunk"] if "chunk" in form else None
        if chunk_field is None or not getattr(chunk_field, "file", None):
            return {"error": "Missing chunk data", "status_code": 400}

        try:
            upload_id = form.getfirst("uploadId", "")
            file_name = form.getfirst("fileName", "")
            chunk_index = int(form.getfirst("chunkIndex", "0"))
            total_chunks = int(form.getfirst("totalChunks", "0"))
            file_size = int(form.getfirst("fileSize", "0"))
        except (TypeError, ValueError):
            return {"error": "Invalid upload metadata", "status_code": 400}

        if not all([upload_id, file_name]) or total_chunks <= 0:
            return {"error": "Missing upload metadata", "status_code": 400}

        chunk_data = chunk_field.file.read()
        return self.service.handle_chunk(
            upload_id=upload_id,
            file_name=file_name,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            file_size=file_size,
            chunk_data=chunk_data,
        )

    def _serve_file(self, file_path: Path) -> None:
        if not file_path.exists() or not file_path.is_file():
            LOGGER.warning("Static file not found: %s", file_path)
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        mime_type, _ = mimetypes.guess_type(str(file_path))
        body = file_path.read_bytes()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003 (BaseHTTPRequestHandler API)
        LOGGER.info("%s - - [%s] " + format, self.address_string(), self.log_date_time_string(), *args)


def run(host: str = "0.0.0.0", port: int = 8000) -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, ScamAppHTTPRequestHandler)
    LOGGER.info("Serving Scam App Scan on http://%s:%s", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down server")
    finally:
        httpd.server_close()


__all__ = ["run", "ScamAppHTTPRequestHandler"]

