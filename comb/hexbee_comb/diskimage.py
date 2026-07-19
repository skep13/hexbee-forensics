"""Raw disk image handling: MBR and GPT partition tables, pure Python.

For deeper filesystem walks (NTFS/ext4/HFS+), `tsk.py` shells out to
The Sleuth Kit when it's installed — Kali ships it — but the partition
map itself never needs external tools.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

SECTOR = 512

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16", 0x05: "Extended", 0x06: "FAT16B",
    0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA",
    0x0F: "Extended LBA", 0x82: "Linux swap", 0x83: "Linux",
    0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xAF: "HFS/HFS+", 0xEE: "GPT protective",
    0xEF: "EFI System",
}

GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
}


@dataclass
class Partition:
    index: int
    scheme: str          # "mbr" | "gpt"
    type_name: str
    start_lba: int
    sectors: int
    bootable: bool = False

    @property
    def start_bytes(self) -> int:
        return self.start_lba * SECTOR

    @property
    def size_bytes(self) -> int:
        return self.sectors * SECTOR


def parse_partitions(image_path: str | Path) -> list[Partition]:
    """Parse the partition table of a raw image. Empty list if none found."""
    image_path = Path(image_path)
    with open(image_path, "rb") as fh:
        mbr = fh.read(SECTOR)
        if len(mbr) < SECTOR or mbr[510:512] != b"\x55\xaa":
            return []
        parts = _parse_mbr(mbr)
        if any(p.type_name == "GPT protective" for p in parts):
            fh.seek(SECTOR)
            gpt_header = fh.read(SECTOR)
            gpt = _parse_gpt(fh, gpt_header)
            if gpt:
                return gpt
        return parts


def _parse_mbr(sector0: bytes) -> list[Partition]:
    parts = []
    for i in range(4):
        entry = sector0[446 + i * 16: 446 + (i + 1) * 16]
        ptype = entry[4]
        if ptype == 0:
            continue
        start_lba, sectors = struct.unpack("<II", entry[8:16])
        parts.append(
            Partition(
                index=i + 1, scheme="mbr",
                type_name=MBR_TYPES.get(ptype, f"type 0x{ptype:02x}"),
                start_lba=start_lba, sectors=sectors,
                bootable=entry[0] == 0x80,
            )
        )
    return parts


def _parse_gpt(fh, header: bytes) -> list[Partition]:
    if header[:8] != b"EFI PART":
        return []
    entries_lba, = struct.unpack("<Q", header[72:80])
    n_entries, = struct.unpack("<I", header[80:84])
    entry_size, = struct.unpack("<I", header[84:88])
    fh.seek(entries_lba * SECTOR)
    blob = fh.read(n_entries * entry_size)
    parts = []
    for i in range(n_entries):
        entry = blob[i * entry_size:(i + 1) * entry_size]
        if len(entry) < 128 or entry[:16] == b"\x00" * 16:
            continue
        type_guid = str(uuid.UUID(bytes_le=entry[:16]))
        first, last = struct.unpack("<QQ", entry[32:48])
        name = entry[56:128].decode("utf-16-le", errors="ignore").rstrip("\x00")
        label = GPT_TYPES.get(type_guid, name or type_guid)
        parts.append(
            Partition(
                index=i + 1, scheme="gpt", type_name=label,
                start_lba=first, sectors=last - first + 1,
            )
        )
    return parts
