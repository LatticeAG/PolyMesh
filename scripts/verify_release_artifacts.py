#!/usr/bin/env python3
"""Reject unsafe or development-only files from release archives."""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable


GOVERNED_DOCUMENT_PATTERNS = (
    "AGENTS.MD",
    "SPEC*.MD",
    "V2-SPEC*.MD",
    "PYTHON-SDK*.MD",
    "CODEIX-REVIEW*.MD",
    "V2-ROADMAP*.MD",
    "POLYMESH-V0.3.0-WHAT-NEXT.MD",
    "V03-ROADMAP-ULTRA.MD",
)
DEVELOPMENT_PATH_PARTS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "build",
    "coverage",
    "node_modules",
    "scripts",
    "templategen",
    "test",
    "tests",
}
DEVELOPMENT_FILENAMES = {
    ".env",
    ".env.local",
    "npm-debug.log",
    "yarn-error.log",
    ".ds_store",
}
FORBIDDEN_SUFFIXES = (".map", ".pyc", ".pyo", ".tsbuildinfo")
CREDENTIAL_FILENAME = re.compile(r"(?:^|[-_.])(secret|credential|private[-_]?key|token)(?:[-_.]|$)", re.IGNORECASE)
CREDENTIAL_CONTENT_PATTERNS = (
    re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(rb"(?i)\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{16,}"),
)
MAX_CONTENT_SCAN_BYTES = 2 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--npm-dir", type=Path, required=True, help="directory containing packed npm tarballs")
    parser.add_argument("--python-dir", type=Path, required=True, help="directory containing built Python wheels")
    return parser.parse_args()


def archive_path_error(member_name: str) -> str | None:
    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts:
        return "unsafe archive path"
    if not member_name or member_name.endswith("/"):
        return None
    normalized_parts = {part.lower() for part in path.parts}
    if normalized_parts.intersection(DEVELOPMENT_PATH_PARTS):
        return "development-only directory"
    filename = path.name
    lower_filename = filename.lower()
    if lower_filename in DEVELOPMENT_FILENAMES or lower_filename.startswith(".env."):
        return "environment or debug file"
    if lower_filename.endswith(FORBIDDEN_SUFFIXES):
        return "source map or compiled development file"
    if CREDENTIAL_FILENAME.search(lower_filename):
        return "credential-like filename"
    upper_filename = filename.upper()
    if any(fnmatch.fnmatchcase(upper_filename, pattern) for pattern in GOVERNED_DOCUMENT_PATTERNS):
        return "governed or internal document"
    return None


def content_error(content: bytes) -> str | None:
    for pattern in CREDENTIAL_CONTENT_PATTERNS:
        if pattern.search(content):
            return "credential-like content"
    return None


def scan_content(stream: BinaryIO | None) -> str | None:
    if stream is None:
        return None
    return content_error(stream.read(MAX_CONTENT_SCAN_BYTES))


def scan_tarball(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                reason = archive_path_error(member.name)
                if reason:
                    problems.append(f"{path.name}:{member.name}: {reason}")
                if member.issym() or member.islnk():
                    problems.append(f"{path.name}:{member.name}: links are not permitted in release archives")
                if member.isfile():
                    reason = scan_content(archive.extractfile(member))
                    if reason:
                        problems.append(f"{path.name}:{member.name}: {reason}")
    except (tarfile.TarError, OSError) as exc:
        problems.append(f"{path.name}: cannot inspect tar archive: {exc}")
    return problems


def scan_wheel(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                reason = archive_path_error(member.filename)
                if reason:
                    problems.append(f"{path.name}:{member.filename}: {reason}")
                if not member.is_dir():
                    with archive.open(member) as stream:
                        reason = content_error(stream.read(MAX_CONTENT_SCAN_BYTES))
                    if reason:
                        problems.append(f"{path.name}:{member.filename}: {reason}")
    except (zipfile.BadZipFile, OSError) as exc:
        problems.append(f"{path.name}: cannot inspect Python wheel: {exc}")
    return problems


def find_archives(directory: Path, suffix: str, label: str) -> list[Path]:
    if not directory.is_dir():
        raise ValueError(f"{label} directory does not exist: {directory}")
    archives = sorted(path for path in directory.iterdir() if path.is_file() and path.name.endswith(suffix))
    if not archives:
        raise ValueError(f"no {label} artifacts found in {directory}")
    return archives


def find_optional_archives(directory: Path, suffix: str) -> list[Path]:
    return sorted(path for path in directory.iterdir() if path.is_file() and path.name.endswith(suffix))


def main() -> int:
    args = parse_args()
    try:
        npm_tarballs = find_archives(args.npm_dir, ".tgz", "npm tarball")
        wheels = find_archives(args.python_dir, ".whl", "Python wheel")
    except ValueError as exc:
        print(f"release artifact scan failed: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []
    for artifact in npm_tarballs:
        problems.extend(scan_tarball(artifact))
    source_distributions = find_optional_archives(args.python_dir, ".tar.gz")
    for artifact in source_distributions:
        problems.extend(scan_tarball(artifact))
    for artifact in wheels:
        problems.extend(scan_wheel(artifact))
    if problems:
        print("release artifact scan failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(
        "release artifact scan passed "
        f"({len(npm_tarballs)} npm tarballs, {len(wheels)} wheel(s), "
        f"{len(source_distributions)} source distribution(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
