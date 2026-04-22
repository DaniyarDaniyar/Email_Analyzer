"""
API Evaluation Script for Email Analyzer
==========================================
Reads .eml/.pdf/.txt files from a JSON dataset (produced by dataset_loader.py),
sends each one to the ``POST /api/detector/scan`` endpoint, collects the
``final_score`` (returned as ``score``) from the response, and saves results
to both CSV and JSON files.

Supports parallel processing with configurable concurrency and rate-limiting.

Usage examples
--------------
# Basic run against a local server, using a previously built dataset:
    python scripts/evaluate_api.py \\
        --dataset ./dataset.json \\
        --api-url http://localhost:8000

# Parallel (5 workers) with rate-limit of 2 requests/second:
    python scripts/evaluate_api.py \\
        --dataset ./dataset.json \\
        --api-url http://localhost:8000 \\
        --workers 5 \\
        --rate-limit 2.0

# Resume a previously interrupted run (checkpoint):
    python scripts/evaluate_api.py \\
        --dataset ./dataset.json \\
        --api-url http://localhost:8000 \\
        --checkpoint ./checkpoint.json \\
        --output-csv ./results.csv \\
        --output-json ./results.json
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Semaphore
from typing import Any

import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("evaluate_api")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_SCAN_PATH = "/api/detector/scan"
REQUEST_TIMEOUT = 60  # seconds


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib-only, no requests dependency required)
# ---------------------------------------------------------------------------

def _multipart_body(fields: dict[str, str], file_field: str, filename: str, file_bytes: bytes, file_content_type: str) -> tuple[bytes, str]:
    """Build a multipart/form-data body from *fields* + one file upload."""
    boundary = "----PythonBoundary" + str(int(time.time() * 1000))
    parts: list[bytes] = []

    for key, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{key}"\r\n'
            f"\r\n"
            f"{value}\r\n".encode()
        )

    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: {file_content_type}\r\n"
        f"\r\n".encode()
        + file_bytes
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def _post_json(url: str, data: dict[str, str], timeout: int = REQUEST_TIMEOUT) -> dict[str, Any]:
    """POST JSON-encoded *data* to *url* and return parsed JSON response."""
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _post_file(url: str, file_bytes: bytes, filename: str, timeout: int = REQUEST_TIMEOUT) -> dict[str, Any]:
    """POST a file to *url* as multipart/form-data and return parsed JSON."""
    ext = Path(filename).suffix.lower()
    mime_map = {".eml": "message/rfc822", ".pdf": "application/pdf", ".txt": "text/plain"}
    file_ct = mime_map.get(ext, "application/octet-stream")
    body, content_type = _multipart_body(
        fields={"input_type": "file"},
        file_field="file",
        filename=filename,
        file_bytes=file_bytes,
        file_content_type=file_ct,
    )
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

def _scan_entry(
    entry: dict[str, Any],
    api_url: str,
    rate_semaphore: Semaphore | None,
    min_interval: float,
    last_call_time: list[float],
    time_lock: Lock,
) -> dict[str, Any]:
    """Send one dataset entry to the API and return a result dict."""
    result: dict[str, Any] = {
        "id": entry.get("id", ""),
        "filename": entry.get("filename", ""),
        "file_type": entry.get("file_type", ""),
        "filepath": entry.get("filepath", ""),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "final_score": None,
        "classification": None,
        "explanation": "",
        "result_id": None,
        "error": None,
    }

    # Rate limiting
    if rate_semaphore is not None:
        rate_semaphore.acquire()
    try:
        if min_interval > 0:
            with time_lock:
                now = time.monotonic()
                elapsed = now - last_call_time[0]
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                last_call_time[0] = time.monotonic()

        scan_url = api_url.rstrip("/") + DEFAULT_SCAN_PATH
        file_type = entry.get("file_type", "").lower()
        filepath = entry.get("filepath", "")

        try:
            if file_type in ("eml", "pdf", "txt") and filepath and Path(filepath).is_file():
                # Upload the original file directly
                file_bytes = Path(filepath).read_bytes()
                response = _post_file(scan_url, file_bytes, Path(filepath).name)
            else:
                # Fall back to sending raw text
                raw = entry.get("raw_content", "")
                response = _post_json(scan_url, {"input_type": "text", "input_data": raw})

            result["status"] = "ok"
            result["final_score"] = response.get("score")
            result["classification"] = response.get("classification")
            result["explanation"] = response.get("explanation", "")
            result["result_id"] = response.get("result_id")

        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            result["status"] = "http_error"
            result["error"] = f"HTTP {exc.code}: {body[:300]}"
            logger.warning("HTTP error for %s: %s", entry.get("filename"), result["error"])
        except urllib.error.URLError as exc:
            result["status"] = "connection_error"
            result["error"] = str(exc.reason)
            logger.warning("Connection error for %s: %s", entry.get("filename"), exc.reason)
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)
            logger.exception("Unexpected error scanning %s", entry.get("filename"))

    finally:
        if rate_semaphore is not None:
            rate_semaphore.release()

    return result


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------

def _load_checkpoint(checkpoint_path: str | Path) -> set[str]:
    """Return set of already-processed file IDs from a checkpoint file."""
    p = Path(checkpoint_path)
    if p.exists():
        try:
            with p.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            ids = set(data.get("processed_ids", []))
            logger.info("Checkpoint loaded: %d already-processed entries.", len(ids))
            return ids
        except Exception as exc:
            logger.warning("Could not load checkpoint (%s); starting fresh.", exc)
    return set()


def _save_checkpoint(checkpoint_path: str | Path, processed_ids: set[str]) -> None:
    p = Path(checkpoint_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump({"processed_ids": sorted(processed_ids)}, fh)


# ---------------------------------------------------------------------------
# Results I/O
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "id",
    "filename",
    "file_type",
    "filepath",
    "scanned_at",
    "status",
    "final_score",
    "classification",
    "explanation",
    "result_id",
    "error",
]


def _append_csv(results: list[dict[str, Any]], csv_path: Path) -> None:
    write_header = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerows(results)


def _save_json(results: list[dict[str, Any]], json_path: Path, meta: dict[str, Any]) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "meta": meta,
        "results": results,
    }
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(output, fh, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate(
    dataset_path: str | Path,
    api_url: str,
    output_csv: str | Path = "results.csv",
    output_json: str | Path = "results.json",
    checkpoint_path: str | Path | None = None,
    workers: int = 1,
    rate_limit: float = 0.0,
    timeout: int = REQUEST_TIMEOUT,
) -> list[dict[str, Any]]:
    """Process all entries in *dataset_path* through the API and save results.

    Parameters
    ----------
    dataset_path:
        Path to JSON dataset produced by ``dataset_loader.py``.
    api_url:
        Base URL of the API (e.g. ``http://localhost:8000``).
    output_csv:
        Where to write/append the CSV results file.
    output_json:
        Where to write the full JSON results file.
    checkpoint_path:
        Optional path for checkpoint file to resume interrupted runs.
    workers:
        Number of parallel threads (default: 1 = sequential).
    rate_limit:
        Maximum requests per second (0 = unlimited).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    list[dict]
        List of result dicts, one per processed entry.

    Example
    -------
    >>> results = evaluate(
    ...     dataset_path="./dataset.json",
    ...     api_url="http://localhost:8000",
    ...     workers=3,
    ...     rate_limit=1.0,
    ... )
    >>> scores = [r["final_score"] for r in results if r["final_score"] is not None]
    >>> print(f"Mean score: {sum(scores)/len(scores):.3f}")
    """
    dataset_path = Path(dataset_path)
    output_csv = Path(output_csv)
    output_json = Path(output_json)

    with dataset_path.open("r", encoding="utf-8") as fh:
        dataset = json.load(fh)

    entries: list[dict[str, Any]] = dataset.get("entries", [])
    if not entries:
        logger.warning("Dataset is empty.")
        return []

    logger.info("Loaded dataset with %d entries.", len(entries))

    # Checkpoint — skip already processed entries
    processed_ids: set[str] = set()
    if checkpoint_path:
        processed_ids = _load_checkpoint(checkpoint_path)

    pending = [e for e in entries if e.get("id") not in processed_ids]
    logger.info(
        "Entries to process: %d  (skipped via checkpoint: %d)",
        len(pending),
        len(entries) - len(pending),
    )

    # Rate-limit helpers
    if rate_limit < 0:
        raise ValueError("rate_limit must be >= 0")
    min_interval = 1.0 / max(rate_limit, 0.001) if rate_limit > 0 else 0.0
    # We use a simple Semaphore to bound concurrent requests and a time-based
    # throttle when rate_limit is set.
    rate_semaphore: Semaphore | None = None
    if workers > 1:
        rate_semaphore = Semaphore(workers)
    last_call_time: list[float] = [0.0]
    time_lock = Lock()

    all_results: list[dict[str, Any]] = []
    write_lock = Lock()

    def _process(entry: dict[str, Any]) -> dict[str, Any]:
        res = _scan_entry(
            entry,
            api_url=api_url,
            rate_semaphore=rate_semaphore,
            min_interval=min_interval,
            last_call_time=last_call_time,
            time_lock=time_lock,
        )
        with write_lock:
            all_results.append(res)
            processed_ids.add(entry.get("id", ""))
            # Incremental CSV write (so progress isn't lost on crash)
            output_csv.parent.mkdir(parents=True, exist_ok=True)
            _append_csv([res], output_csv)
            if checkpoint_path:
                _save_checkpoint(checkpoint_path, processed_ids)
            logger.info(
                "[%d/%d] %s -> status=%s  score=%s",
                len(all_results),
                len(pending),
                entry.get("filename"),
                res["status"],
                res["final_score"],
            )
        return res

    if workers <= 1:
        for entry in pending:
            _process(entry)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_process, e): e for e in pending}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Unhandled worker error: %s", exc)

    meta = {
        "api_url": api_url,
        "dataset_path": str(dataset_path),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(entries),
        "processed": len(all_results),
        "workers": workers,
        "rate_limit": rate_limit,
    }
    _save_json(all_results, output_json, meta)
    logger.info(
        "Evaluation complete. Results saved to %s (CSV) and %s (JSON).",
        output_csv,
        output_json,
    )
    return all_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Evaluate emails against the scan API and collect final scores.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--dataset",
        required=True,
        metavar="FILE",
        help="Path to dataset JSON produced by dataset_loader.py.",
    )
    p.add_argument(
        "--api-url",
        required=True,
        metavar="URL",
        help="Base URL of the API (e.g. http://localhost:8000).",
    )
    p.add_argument(
        "--output-csv",
        default="results.csv",
        metavar="FILE",
        help="Output CSV file (default: results.csv).",
    )
    p.add_argument(
        "--output-json",
        default="results.json",
        metavar="FILE",
        help="Output JSON file (default: results.json).",
    )
    p.add_argument(
        "--checkpoint",
        default=None,
        metavar="FILE",
        help="Checkpoint JSON file for resumable runs.",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel threads (default: 1).",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="RPS",
        help="Maximum requests per second (default: 0 = unlimited).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=REQUEST_TIMEOUT,
        metavar="SEC",
        help=f"HTTP timeout in seconds (default: {REQUEST_TIMEOUT}).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    evaluate(
        dataset_path=args.dataset,
        api_url=args.api_url,
        output_csv=args.output_csv,
        output_json=args.output_json,
        checkpoint_path=args.checkpoint,
        workers=args.workers,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
