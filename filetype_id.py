#!/usr/bin/env python3
"""Identify common file types from content rather than file extensions."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FileType:
    description: str
    mime_type: str
    extensions: tuple[str, ...]
    signature: str


@dataclass(frozen=True)
class FileResult:
    path: str
    size: int
    detected_type: str
    mime_type: str
    expected_extensions: tuple[str, ...]
    actual_extension: str
    extension_matches: bool | None
    signature: str


@dataclass(frozen=True)
class FileError:
    path: str
    error: str


SIGNATURES: tuple[tuple[bytes, FileType], ...] = (
    (b"\x89PNG\r\n\x1a\n", FileType("PNG image", "image/png", (".png",), "PNG signature")),
    (b"\xff\xd8\xff", FileType("JPEG image", "image/jpeg", (".jpg", ".jpeg"), "JPEG signature")),
    (b"GIF87a", FileType("GIF image", "image/gif", (".gif",), "GIF87a signature")),
    (b"GIF89a", FileType("GIF image", "image/gif", (".gif",), "GIF89a signature")),
    (b"BM", FileType("BMP image", "image/bmp", (".bmp",), "BMP signature")),
    (b"II*\x00", FileType("TIFF image", "image/tiff", (".tif", ".tiff"), "little-endian TIFF signature")),
    (b"MM\x00*", FileType("TIFF image", "image/tiff", (".tif", ".tiff"), "big-endian TIFF signature")),
    (b"\x00\x00\x01\x00", FileType("ICO image", "image/vnd.microsoft.icon", (".ico",), "ICO signature")),
    (b"%PDF-", FileType("PDF document", "application/pdf", (".pdf",), "PDF header")),
    (b"PK\x03\x04", FileType("ZIP archive", "application/zip", (".zip",), "ZIP local-file header")),
    (b"PK\x05\x06", FileType("ZIP archive", "application/zip", (".zip",), "ZIP empty-archive header")),
    (b"PK\x07\x08", FileType("ZIP archive", "application/zip", (".zip",), "ZIP spanning header")),
    (b"\x1f\x8b", FileType("GZIP archive", "application/gzip", (".gz", ".tar.gz", ".tgz"), "GZIP signature")),
    (b"BZh", FileType("BZIP2 archive", "application/x-bzip2", (".bz2", ".tar.bz2", ".tbz", ".tbz2"), "BZIP2 signature")),
    (b"\xfd7zXZ\x00", FileType("XZ archive", "application/x-xz", (".xz", ".tar.xz", ".txz"), "XZ signature")),
    (b"7z\xbc\xaf\x27\x1c", FileType("7-Zip archive", "application/x-7z-compressed", (".7z",), "7-Zip signature")),
    (b"Rar!\x1a\x07\x00", FileType("RAR archive", "application/vnd.rar", (".rar",), "RAR 4 signature")),
    (b"Rar!\x1a\x07\x01\x00", FileType("RAR archive", "application/vnd.rar", (".rar",), "RAR 5 signature")),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", FileType("OLE compound document", "application/x-ole-storage", (".doc", ".xls", ".ppt"), "OLE compound document signature")),
    (b"SQLite format 3\x00", FileType("SQLite database", "application/vnd.sqlite3", (".sqlite", ".sqlite3", ".db"), "SQLite 3 header")),
    (b"\xca\xfe\xba\xbe", FileType("Java class file", "application/java-vm", (".class",), "Java class magic")),
    (b"\x00asm", FileType("WebAssembly module", "application/wasm", (".wasm",), "WebAssembly magic")),
    (b"fLaC", FileType("FLAC audio", "audio/flac", (".flac",), "FLAC signature")),
    (b"OggS", FileType("Ogg container", "application/ogg", (".ogg", ".ogv", ".oga"), "Ogg page header")),
    (b"ID3", FileType("MP3 audio", "audio/mpeg", (".mp3",), "ID3 tag")),
)


def _type_from_header(header: bytes) -> FileType | None:
    for signature, file_type in SIGNATURES:
        if header.startswith(signature):
            return file_type

    if len(header) >= 12 and header[:4] == b"RIFF":
        if header[8:12] == b"WEBP":
            return FileType("WebP image", "image/webp", (".webp",), "RIFF/WEBP signature")
        if header[8:12] == b"WAVE":
            return FileType("WAV audio", "audio/wav", (".wav",), "RIFF/WAVE signature")

    if len(header) >= 262 and header[257:262] == b"ustar":
        return FileType("TAR archive", "application/x-tar", (".tar",), "ustar header")

    if header.startswith(b"\x7fELF"):
        return FileType("ELF executable or object", "application/x-elf", (), "ELF magic")

    if header.startswith(b"MZ"):
        if len(header) >= 64:
            pe_offset = int.from_bytes(header[60:64], "little")
            if pe_offset + 4 <= len(header) and header[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                return FileType("Windows PE executable", "application/vnd.microsoft.portable-executable", (".exe", ".dll"), "MZ and PE signatures")
        return FileType("DOS executable (MZ; PE not confirmed)", "application/x-dosexec", (".exe", ".com"), "MZ signature")

    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return FileType("Mach-O executable or object", "application/x-mach-binary", (), "Mach-O magic")

    return None


def _is_text(header: bytes) -> bool:
    if header.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    try:
        text = header.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "\x00" in text:
        return False
    controls = sum(1 for char in text if ord(char) < 32 and char not in "\t\n\r\f\b")
    return not text or controls / len(text) <= 0.05


def _actual_extension(path: Path) -> str:
    name = path.name.lower()
    for compound_extension in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if name.endswith(compound_extension):
            return compound_extension
    return path.suffix.lower()


def identify(path: Path) -> FileResult:
    size = path.stat().st_size
    with path.open("rb") as file:
        header = file.read(8192)

    file_type = _type_from_header(header)
    if file_type is None:
        if _is_text(header):
            file_type = FileType("Text file (encoding or format not determined)", "text/plain", (), "text-content heuristic")
        else:
            file_type = FileType("Unknown binary data", "application/octet-stream", (), "no known signature matched")

    extension = _actual_extension(path)
    matches = None if not file_type.extensions else extension in file_type.extensions
    return FileResult(
        path=str(path),
        size=size,
        detected_type=file_type.description,
        mime_type=file_type.mime_type,
        expected_extensions=file_type.extensions,
        actual_extension=extension or "(none)",
        extension_matches=matches,
        signature=file_type.signature,
    )


def _collect_files(paths: Iterable[Path], recursive: bool) -> tuple[list[Path], list[FileError]]:
    files: list[Path] = []
    errors: list[FileError] = []
    for path in paths:
        try:
            if path.is_dir():
                if not recursive:
                    errors.append(FileError(str(path), "is a directory; pass --recursive to scan directories"))
                    continue
                for root, directories, filenames in os.walk(path, followlinks=False):
                    directories.sort()
                    for filename in sorted(filenames):
                        files.append(Path(root) / filename)
            else:
                files.append(path)
        except OSError as error:
            errors.append(FileError(str(path), str(error)))
    return files, errors


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Identify common file types from their content and flag known extension mismatches."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="one or more files or directories")
    parser.add_argument("-r", "--recursive", action="store_true", help="scan files in directories recursively")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--check", action="store_true", help="exit with status 1 if a known extension mismatch is found")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    files, errors = _collect_files(args.paths, args.recursive)
    results: list[FileResult] = []
    for path in files:
        try:
            results.append(identify(path))
        except OSError as error:
            errors.append(FileError(str(path), str(error)))

    if args.json:
        print(json.dumps(
            {
                "results": [asdict(result) for result in results],
                "errors": [asdict(error) for error in errors],
            },
            indent=2,
        ))
    else:
        for result in results:
            if result.extension_matches is False:
                status = "MISMATCH"
            elif result.extension_matches is True:
                status = "match"
            else:
                status = "not checked"
            print(f"{result.path}: {result.detected_type} [{result.mime_type}]")
            print(f"  Extension: {result.actual_extension} ({status}); signature: {result.signature}")
        for error in errors:
            print(f"ERROR: {error.path}: {error.error}", file=sys.stderr)

    if errors:
        return 2
    if args.check and any(result.extension_matches is False for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
