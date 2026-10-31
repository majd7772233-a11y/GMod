#!/usr/bin/env python3
"""Download, inventory, safely extract and ClamAV-scan a remote ZIP in CI.

Extracted payloads are temporary and are deliberately NOT committed or uploaded.
Only small inspection reports are written to reports/latest/.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

import requests

ROOT = Path.cwd()
REPORT_DIR = ROOT / "reports" / "latest"
WORK_DIR = ROOT / ".zip-inspector-work"
ARCHIVE_PATH = WORK_DIR / "source.zip"
EXTRACT_DIR = WORK_DIR / "extracted"
CHUNK_SIZE = 8 * 1024 * 1024
MAX_FILES = 150_000
MAX_SINGLE_FILE_GIB = 2.0
MAX_RATIO = 1000
USER_AGENT = "GMod-Cloud-ZIP-Inspector/1.0"


def gib(value: int) -> float:
    return round(value / (1024 ** 3), 3)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def safe_member_path(name: str, root: Path) -> Path | None:
    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts if part != ""):
        return None
    if any("\x00" in part for part in parts):
        return None
    target = root.joinpath(*[part for part in parts if part])
    try:
        target.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return target


def head_metadata(url: str) -> tuple[int | None, bool]:
    response = requests.head(
        url,
        allow_redirects=True,
        timeout=(30, 60),
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
    )
    try:
        response.raise_for_status()
        length_header = response.headers.get("Content-Length")
        length = int(length_header) if length_header and length_header.isdigit() else None
        ranges = "bytes" in response.headers.get("Accept-Ranges", "").lower()
        return length, ranges
    finally:
        response.close()


def download_with_resume(url: str, expected_size: int | None) -> int:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    attempts = 0

    while attempts < 8:
        offset = ARCHIVE_PATH.stat().st_size if ARCHIVE_PATH.exists() else 0
        if expected_size is not None and offset == expected_size:
            return offset

        headers = {}
        if offset:
            headers["Range"] = f"bytes={offset}-"

        try:
            response = session.get(
                url,
                headers=headers,
                stream=True,
                allow_redirects=True,
                timeout=(30, 180),
            )

            if offset and response.status_code == 200:
                # Origin ignored Range. Restart safely rather than appending a second copy.
                response.close()
                ARCHIVE_PATH.unlink(missing_ok=True)
                continue

            if offset and response.status_code != 206:
                response.raise_for_status()
                raise RuntimeError(f"Server did not honor byte range (HTTP {response.status_code}).")

            if not offset and response.status_code not in (200, 206):
                response.raise_for_status()

            if response.status_code == 206:
                content_range = response.headers.get("Content-Range", "")
                match = re.match(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", content_range)
                if not match or int(match.group(1)) != offset:
                    response.close()
                    raise RuntimeError(f"Unexpected Content-Range: {content_range!r}")

            mode = "ab" if offset else "wb"
            with ARCHIVE_PATH.open(mode) as output:
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    if chunk:
                        output.write(chunk)
            response.close()

            actual = ARCHIVE_PATH.stat().st_size
            if expected_size is None or actual == expected_size:
                return actual
            if actual > expected_size:
                raise RuntimeError(f"Downloaded {actual} bytes, expected only {expected_size}.")
            print(f"Download resumed at {gib(actual):.3f} GiB / {gib(expected_size):.3f} GiB")
        except Exception as exc:
            attempts += 1
            print(f"Download attempt {attempts}/8 interrupted: {exc}")
            if attempts >= 8:
                raise
            time.sleep(min(60, 5 * attempts))

    raise RuntimeError("Download retry limit reached.")


def run_clamav(target: Path, log_path: Path, recursive: bool) -> dict[str, Any]:
    command = [
        "clamscan",
        "--infected",
        "--alert-exceeds-max=yes",
        "--max-filesize=2000M",
        "--max-scansize=7000M",
        "--max-files=150000",
        "--max-recursion=30",
        "--log=" + str(log_path),
    ]
    if recursive:
        command.append("--recursive")
    command.append(str(target))

    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=4 * 60 * 60)
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        found = " FOUND" in combined or " FOUND" in log_path.read_text(errors="replace") if log_path.exists() else " FOUND" in combined
        limit_alert = "Heuristics.Limits.Exceeded" in combined
        if log_path.exists():
            log_content = log_path.read_text(errors="replace")
            found = found or " FOUND" in log_content
            limit_alert = limit_alert or "Heuristics.Limits.Exceeded" in log_content
        return {
            "return_code": result.returncode,
            "infected_detected": bool(found),
            "scan_limit_alert": bool(limit_alert),
            "stdout_tail": combined[-4000:],
            "log": str(log_path.relative_to(ROOT)),
        }
    except subprocess.TimeoutExpired:
        return {"return_code": 2, "error": "ClamAV scan timed out.", "infected_detected": False, "scan_limit_alert": True}
    except FileNotFoundError:
        return {"return_code": 2, "error": "clamscan executable not found.", "infected_detected": False, "scan_limit_alert": True}


def make_tree(rows: list[dict[str, Any]], output: Path) -> None:
    lines = []
    rows_sorted = sorted(rows, key=lambda item: item["path"].lower())
    for row in rows_sorted:
        path = row["path"]
        depth = path.count("/")
        size = row.get("size", 0)
        label = "[DIR]" if row.get("is_dir") else f"[{size:,} bytes]"
        status = f" ({row['status']})" if row.get("status") else ""
        lines.append(f"{'  ' * depth}{label} {path}{status}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def inspect_and_extract(max_extract_bytes: int) -> dict[str, Any]:
    source_url = os.environ.get("SOURCE_URL", "").strip()
    if not source_url.lower().startswith("https://"):
        raise ValueError("Only HTTPS source URLs are accepted.")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    expected_size, accepts_ranges = head_metadata(source_url)
    if expected_size is None:
        raise RuntimeError("The source did not provide a reliable Content-Length; refusing an unbounded download.")
    if expected_size > 3 * (1024 ** 3):
        raise RuntimeError(f"Archive is larger than the 3 GiB safety limit: {gib(expected_size)} GiB.")

    print(f"Remote archive size: {gib(expected_size)} GiB; byte ranges: {accepts_ranges}")
    downloaded = download_with_resume(source_url, expected_size)

    import zipfile

    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    total_uncompressed = 0
    encrypted = 0
    unsafe_paths = 0
    symlinks = 0
    too_large_members = 0

    with zipfile.ZipFile(ARCHIVE_PATH, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise RuntimeError(f"Archive contains {len(infos):,} entries; limit is {MAX_FILES:,}.")

        for info in infos:
            raw_name = info.filename
            is_dir = info.is_dir()
            target = safe_member_path(raw_name, EXTRACT_DIR)
            status = "listed"
            mode = (info.external_attr >> 16) & 0xFFFF
            is_link = stat.S_ISLNK(mode)

            if target is None:
                status = "rejected-unsafe-path"
                unsafe_paths += 1
            elif is_link:
                status = "rejected-symlink"
                symlinks += 1
            elif info.flag_bits & 0x1:
                status = "encrypted-not-inspected"
                encrypted += 1
            elif info.file_size > int(MAX_SINGLE_FILE_GIB * (1024 ** 3)):
                status = "skipped-member-over-2GiB"
                too_large_members += 1
            elif info.file_size and info.compress_size == 0:
                status = "suspicious-zero-compressed-size"
            elif info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                status = "skipped-extreme-compression-ratio"
            else:
                total_uncompressed += info.file_size

            rows.append({
                "path": raw_name,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "compression": info.compress_type,
                "is_dir": is_dir,
                "status": status,
            })

        if total_uncompressed > max_extract_bytes:
            raise RuntimeError(
                f"Declared uncompressed size {gib(total_uncompressed)} GiB exceeds "
                f"the configured limit {gib(max_extract_bytes)} GiB."
            )

        EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
        extracted_count = 0
        for info, row in zip(infos, rows):
            if row["status"] != "listed":
                continue
            target = safe_member_path(info.filename, EXTRACT_DIR)
            if target is None:
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                row["status"] = "directory-created"
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as src, target.open("wb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size or written > int(MAX_SINGLE_FILE_GIB * (1024 ** 3)):
                            raise RuntimeError("Member expanded beyond its declared safety limit.")
                        dst.write(chunk)
                if written != info.file_size:
                    raise RuntimeError(f"Size mismatch: expected {info.file_size}, wrote {written}.")
                row["status"] = "extracted"
                extracted_count += 1
            except Exception as exc:
                row["status"] = "extraction-error"
                errors.append(f"{info.filename}: {exc}")
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass

    # Store the inventory/tree before malware scans so useful metadata survives scan errors.
    with (REPORT_DIR / "inventory.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "path", "size", "compressed_size", "compression", "is_dir", "status"
        ])
        writer.writeheader()
        writer.writerows(rows)

    make_tree(rows, REPORT_DIR / "tree.txt")

    archive_scan = run_clamav(ARCHIVE_PATH, REPORT_DIR / "archive-scan.log", recursive=False)
    extracted_scan = run_clamav(EXTRACT_DIR, REPORT_DIR / "extracted-scan.log", recursive=True)

    incomplete = bool(
        errors or encrypted or unsafe_paths or symlinks or too_large_members
        or any(row["status"].startswith("skipped") or row["status"].startswith("rejected")
               or row["status"] == "encrypted-not-inspected" for row in rows)
    )
    infected = archive_scan.get("infected_detected", False) or extracted_scan.get("infected_detected", False)
    scan_error = archive_scan.get("return_code") == 2 or extracted_scan.get("return_code") == 2
    scan_limited = archive_scan.get("scan_limit_alert", False) or extracted_scan.get("scan_limit_alert", False)

    status = "INFECTED" if infected else (
        "INCOMPLETE_OR_UNSCANNED" if incomplete or scan_error or scan_limited else "NO_DETECTION"
    )

    summary = {
        "source_url": source_url,
        "archive_bytes": downloaded,
        "archive_gib": gib(downloaded),
        "accept_ranges_advertised": accepts_ranges,
        "zip_entries": len(rows),
        "declared_uncompressed_bytes": total_uncompressed,
        "declared_uncompressed_gib": gib(total_uncompressed),
        "extracted_files": extracted_count,
        "encrypted_entries": encrypted,
        "unsafe_paths_rejected": unsafe_paths,
        "symlinks_rejected": symlinks,
        "members_over_2gib_skipped": too_large_members,
        "extraction_errors": errors,
        "archive_scan": archive_scan,
        "extracted_scan": extracted_scan,
        "status": status,
        "payload_published": False,
        "note": "Extracted files remained in the temporary hosted runner and were not committed or uploaded.",
    }
    write_json(REPORT_DIR / "summary.json", summary)
    (REPORT_DIR / "errors.txt").write_text("\n".join(errors) if errors else "No extraction errors recorded.\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if status != "NO_DETECTION":
        raise RuntimeError(f"Inspection result is {status}; see reports/latest/ for details.")
    return summary


def main() -> int:
    try:
        max_gib = float(os.environ.get("MAX_EXTRACT_GIB", "6"))
        if not (0.5 <= max_gib <= 8):
            raise ValueError("MAX_EXTRACT_GIB must be between 0.5 and 8.")
        summary = inspect_and_extract(int(max_gib * (1024 ** 3)))
        return 0 if summary["status"] == "NO_DETECTION" else 2
    except Exception as exc:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        summary_path = REPORT_DIR / "summary.json"
        existing = {}
        if summary_path.exists():
            try:
                existing = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        existing.update({
            "status": existing.get("status", "ERROR"),
            "error": str(exc),
            "payload_published": False,
            "note": "No extracted payload was committed or uploaded.",
        })
        write_json(summary_path, existing)
        with (REPORT_DIR / "errors.txt").open("a", encoding="utf-8") as handle:
            handle.write(str(exc) + "\n")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        # Never retain the remote archive or extracted payload in the repository workspace.
        shutil.rmtree(WORK_DIR, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
