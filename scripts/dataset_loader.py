"""
Dataset Loader for Email Analyzer
==================================
Scans a directory for .eml, .pdf, and .txt files, loads them into a JSON
dataset with optional caching and indexing.

Usage examples
--------------
# Build (or refresh) a dataset from a folder of emails:
    python scripts/dataset_loader.py --input-dir ./emails --output ./dataset.json

# Force rebuild even if cache exists:
    python scripts/dataset_loader.py --input-dir ./emails --output ./dataset.json --rebuild

# List the contents of an existing dataset:
    python scripts/dataset_loader.py --list --output ./dataset.json
"""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dataset_loader")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SUPPORTED_EXTENSIONS = {".eml", ".pdf", ".txt"}
DATASET_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_checksum(path: Path, chunk_size: int = 1 << 16) -> str:
    """Return SHA-256 hex digest of *path* content."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _read_eml(path: Path) -> dict[str, Any]:
    """Parse an .eml file and return a metadata + raw_content dict."""
    raw = path.read_bytes()
    msg = email.message_from_bytes(raw, policy=policy.default)
    subject = str(msg.get("subject", ""))
    sender = str(msg.get("from", ""))
    recipient = str(msg.get("to", ""))
    date_str = str(msg.get("date", ""))

    # Extract plain-text body (first text/plain part, or fallback to full raw)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    body = part.get_content()
                except Exception:
                    body = ""
                break
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = raw.decode("utf-8", errors="replace")

    return {
        "subject": subject,
        "from": sender,
        "to": recipient,
        "date": date_str,
        "body_preview": body[:500],
        "raw_content": raw.decode("utf-8", errors="replace"),
    }


def _read_txt(path: Path) -> dict[str, Any]:
    """Read a plain-text file."""
    content = path.read_text(encoding="utf-8", errors="replace")
    return {
        "raw_content": content,
        "body_preview": content[:500],
    }


def _read_pdf(path: Path) -> dict[str, Any]:
    """Read text from a PDF file (requires pdfminer.six or PyPDF2 if available)."""
    content = ""
    try:
        import pdfminer.high_level as pdfminer_hl  # type: ignore
        import io

        content = pdfminer_hl.extract_text(io.BytesIO(path.read_bytes()))
    except ImportError:
        try:
            import PyPDF2  # type: ignore

            reader = PyPDF2.PdfReader(str(path))
            content = "\n".join(
                page.extract_text() or "" for page in reader.pages
            )
        except ImportError:
            logger.warning(
                "Neither pdfminer.six nor PyPDF2 found; storing PDF as base64."
            )
            import base64

            content = base64.b64encode(path.read_bytes()).decode()
    except Exception as exc:
        logger.warning("Could not extract text from PDF %s: %s", path, exc)

    return {
        "raw_content": content,
        "body_preview": content[:500],
    }


def scan_directory(input_dir: str | Path) -> list[Path]:
    """Return sorted list of supported files under *input_dir* (recursive)."""
    root = Path(input_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            found.append(path)

    logger.info("Found %d file(s) in %s", len(found), root)
    return found


def load_file(path: Path) -> dict[str, Any]:
    """Load a single file and return a dataset entry dict."""
    ext = path.suffix.lower()
    entry: dict[str, Any] = {
        "id": _file_checksum(path)[:16],
        "filename": path.name,
        "filepath": str(path),
        "file_type": ext.lstrip("."),
        "file_size_bytes": path.stat().st_size,
        "checksum": _file_checksum(path),
        "loaded_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if ext == ".eml":
            entry.update(_read_eml(path))
        elif ext == ".txt":
            entry.update(_read_txt(path))
        elif ext == ".pdf":
            entry.update(_read_pdf(path))
    except Exception as exc:
        logger.error("Failed to read %s: %s", path, exc)
        entry["error"] = str(exc)
        entry["raw_content"] = ""

    return entry


# ---------------------------------------------------------------------------
# Dataset I/O
# ---------------------------------------------------------------------------

def _load_existing_dataset(output_path: Path) -> dict[str, Any]:
    if output_path.exists():
        try:
            with output_path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Could not read existing dataset (%s); starting fresh.", exc)
    return {}


def build_dataset(
    input_dir: str | Path,
    output_path: str | Path,
    rebuild: bool = False,
) -> dict[str, Any]:
    """Scan *input_dir*, load all supported files, and save a JSON dataset.

    Parameters
    ----------
    input_dir:
        Root directory to scan for email/document files.
    output_path:
        Where to write (or update) the JSON dataset file.
    rebuild:
        When *True*, ignore any cached data and re-load every file.

    Returns
    -------
    dict
        The full dataset dict that was saved to *output_path*.

    Example
    -------
    >>> ds = build_dataset("./emails", "./dataset.json")
    >>> print(ds["meta"]["total_files"])
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Load cache (existing dataset keyed by checksum)
    existing: dict[str, Any] = {}
    if not rebuild:
        raw = _load_existing_dataset(output_path)
        existing = {entry["checksum"]: entry for entry in raw.get("entries", []) if "checksum" in entry}

    files = scan_directory(input_dir)

    entries: list[dict[str, Any]] = []
    new_count = 0
    cached_count = 0

    for path in files:
        checksum = _file_checksum(path)
        if checksum in existing and not rebuild:
            entries.append(existing[checksum])
            cached_count += 1
            logger.debug("Cached: %s", path.name)
        else:
            entry = load_file(path)
            entries.append(entry)
            new_count += 1
            logger.info("Loaded: %s", path.name)

    # Build index (filename -> list of positions)
    index: dict[str, list[int]] = {}
    for i, entry in enumerate(entries):
        key = entry.get("filename", "")
        index.setdefault(key, []).append(i)

    dataset: dict[str, Any] = {
        "meta": {
            "version": DATASET_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_directory": str(Path(input_dir).resolve()),
            "total_files": len(entries),
            "new_files": new_count,
            "cached_files": cached_count,
        },
        "index": index,
        "entries": entries,
    }

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(dataset, fh, ensure_ascii=False, indent=2)

    logger.info(
        "Dataset saved to %s  (total=%d  new=%d  cached=%d)",
        output_path,
        len(entries),
        new_count,
        cached_count,
    )
    return dataset


def list_dataset(output_path: str | Path) -> None:
    """Pretty-print a summary of an existing dataset file."""
    path = Path(output_path)
    if not path.exists():
        print(f"Dataset file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with path.open("r", encoding="utf-8") as fh:
        ds = json.load(fh)

    meta = ds.get("meta", {})
    print(f"Dataset: {path}")
    print(f"  Version    : {meta.get('version', 'n/a')}")
    print(f"  Created    : {meta.get('created_at', 'n/a')}")
    print(f"  Source dir : {meta.get('source_directory', 'n/a')}")
    print(f"  Total files: {meta.get('total_files', len(ds.get('entries', [])))}")
    print()
    for i, entry in enumerate(ds.get("entries", []), 1):
        status = "ERROR" if entry.get("error") else "OK"
        print(f"  [{i:4d}] [{status}] {entry.get('file_type','?'):4s}  {entry.get('filename','?')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Load and manage an .eml/.pdf/.txt dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--input-dir",
        metavar="DIR",
        help="Directory to scan for email/document files.",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default="dataset.json",
        help="Path to the output JSON dataset file (default: dataset.json).",
    )
    p.add_argument(
        "--rebuild",
        action="store_true",
        help="Ignore cache and re-load all files.",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="List the contents of an existing dataset and exit.",
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

    if args.list:
        list_dataset(args.output)
        return

    if not args.input_dir:
        parser.error("--input-dir is required unless --list is specified.")

    build_dataset(
        input_dir=args.input_dir,
        output_path=args.output,
        rebuild=args.rebuild,
    )


if __name__ == "__main__":
    main()
