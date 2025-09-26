# Manual Test Log

## 2025-09-26: test.apk Upload Regression Check
- Started the lightweight HTTP server via `PYTHONPATH=Web python -c "from simple_server import run; run()"`.
- Triggered a drag-and-drop upload of `test.apk` through the browser UI using an automated Playwright script that streams 5 MB chunks to `/api/upload-chunk`.
- Observed the modal report once analysis completed; server logs confirmed the polling cycle and final success response.

Artifacts for this run are captured in the accompanying task transcript.
