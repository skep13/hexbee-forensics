"""File-type identification by magic bytes, and extension-mismatch triage.

An executable renamed to `holiday.jpg` is one of the oldest tricks in the
book; signature-vs-extension disagreement is a high-value triage signal.
"""

from __future__ import annotations

# (signature bytes, offset, type name, canonical extensions)
SIGNATURES: list[tuple[bytes, int, str, tuple[str, ...]]] = [
    (b"\xff\xd8\xff", 0, "jpeg", ("jpg", "jpeg", "jfif")),
    (b"\x89PNG\r\n\x1a\n", 0, "png", ("png",)),
    (b"GIF87a", 0, "gif", ("gif",)),
    (b"GIF89a", 0, "gif", ("gif",)),
    (b"%PDF", 0, "pdf", ("pdf",)),
    (b"PK\x03\x04", 0, "zip", ("zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "epub")),
    (b"Rar!\x1a\x07", 0, "rar", ("rar",)),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", ("7z",)),
    (b"\x1f\x8b", 0, "gzip", ("gz", "tgz")),
    (b"MZ", 0, "pe_executable", ("exe", "dll", "sys", "scr", "com")),
    (b"\x7fELF", 0, "elf_executable", ("elf", "so", "bin", "")),
    # "" because extensionless SQLite is normal (Chrome History, Cookies, ...)
    (b"SQLite format 3\x00", 0, "sqlite", ("db", "sqlite", "sqlite3", "")),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole2", ("doc", "xls", "ppt", "msi")),
    (b"ftyp", 4, "mp4", ("mp4", "mov", "m4a", "m4v", "3gp", "heic")),
    (b"ID3", 0, "mp3", ("mp3",)),
    (b"OggS", 0, "ogg", ("ogg", "opus")),
    (b"RIFF", 0, "riff", ("wav", "avi", "webp")),
    (b"BM", 0, "bmp", ("bmp",)),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "windows_lnk", ("lnk",)),
    (b"regf", 0, "windows_registry", ("dat", "hiv", "")),
]

HEADER_LEN = 32


def identify(header: bytes) -> str | None:
    """Best-effort file type from the first HEADER_LEN bytes."""
    for sig, offset, name, _exts in SIGNATURES:
        if header[offset:offset + len(sig)] == sig:
            return name
    return None


def extension_mismatch(magic_type: str | None, filename: str) -> bool:
    """True when the magic type is known and the extension disagrees.

    Only flags types where masquerading matters — an extensionless ELF on
    Linux is normal, so empty string in the canonical set suppresses it.
    """
    if magic_type is None:
        return False
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    for _sig, _off, name, exts in SIGNATURES:
        if name == magic_type:
            if ext in exts:
                return False
    return True


EXECUTABLE_TYPES = {"pe_executable", "elf_executable"}
