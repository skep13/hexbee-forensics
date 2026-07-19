"""Comb analysis toolkit: magic, inventory, carving, partitions, browser
history, EXIF GPS, and the scan pipeline."""

import sqlite3
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "comb"))

from hexbee_comb.analysis import scan, to_hive_events
from hexbee_comb.browser import parse_chrome, parse_firefox
from hexbee_comb.carver import carve
from hexbee_comb.diskimage import parse_partitions
from hexbee_comb.exif import extract as extract_exif
from hexbee_comb.inventory import walk
from hexbee_comb.magic import extension_mismatch, identify

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9"
PNG = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"IEND\xaeB`\x82")
PDF = b"%PDF-1.7\nhello forensic world\n%%EOF"


# -- magic ----------------------------------------------------------------

def test_identify_and_mismatch():
    assert identify(JPEG[:32]) == "jpeg"
    assert identify(b"MZ\x90\x00" + b"\x00" * 28) == "pe_executable"
    assert identify(b"\x00" * 32) is None
    assert extension_mismatch("pe_executable", "holiday.jpg") is True
    assert extension_mismatch("pe_executable", "setup.exe") is False
    assert extension_mismatch("jpeg", "photo.jpeg") is False
    assert extension_mismatch(None, "whatever.xyz") is False
    # extensionless ELF is normal on Linux — suppressed
    assert extension_mismatch("elf_executable", "httpd") is False


# -- inventory ------------------------------------------------------------

def test_inventory_flags_masquerading_exe(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "report.pdf").write_bytes(PDF)
    (tmp_path / "docs" / "holiday.jpg").write_bytes(b"MZ" + b"\x00" * 100)
    records = {r.path.replace("\\", "/"): r for r in walk(tmp_path)}
    assert records["docs/report.pdf"].magic_type == "pdf"
    assert not records["docs/report.pdf"].mismatch
    bad = records["docs/holiday.jpg"]
    assert bad.magic_type == "pe_executable" and bad.mismatch and bad.executable


# -- carving --------------------------------------------------------------

def test_carve_recovers_embedded_files(tmp_path):
    image = tmp_path / "usb.raw"
    blob = (b"\x00" * 500 + JPEG + b"\xff" * 300 + PNG + b"\x00" * 200 + PDF
            + b"\x00" * 100)
    image.write_bytes(blob)
    out = tmp_path / "carved"
    results = carve(image, out)
    kinds = sorted(r.kind for r in results)
    assert kinds == ["jpeg", "pdf", "png"]
    jpeg = next(r for r in results if r.kind == "jpeg")
    assert jpeg.offset == 500 and jpeg.size == len(JPEG)
    assert Path(jpeg.path).read_bytes() == JPEG


# -- partitions -----------------------------------------------------------

def _mbr_image(tmp_path) -> Path:
    sector0 = bytearray(512)
    entry = bytearray(16)
    entry[0] = 0x80                      # bootable
    entry[4] = 0x0B                      # FAT32
    entry[8:12] = struct.pack("<I", 2048)
    entry[12:16] = struct.pack("<I", 100_000)
    sector0[446:462] = entry
    sector0[510:512] = b"\x55\xaa"
    path = tmp_path / "disk.raw"
    path.write_bytes(bytes(sector0) + b"\x00" * 512)
    return path


def test_parse_mbr(tmp_path):
    parts = parse_partitions(_mbr_image(tmp_path))
    assert len(parts) == 1
    p = parts[0]
    assert p.scheme == "mbr" and p.type_name == "FAT32"
    assert p.start_lba == 2048 and p.sectors == 100_000 and p.bootable


def test_no_partition_table(tmp_path):
    blank = tmp_path / "blank.raw"
    blank.write_bytes(b"\x00" * 1024)
    assert parse_partitions(blank) == []


# -- browser history ------------------------------------------------------

def _chrome_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT,
        title TEXT, visit_count INTEGER, last_visit_time INTEGER)""")
    from datetime import datetime, timezone
    delta = (datetime(2026, 7, 18, tzinfo=timezone.utc)
             - datetime(1601, 1, 1, tzinfo=timezone.utc))
    webkit = int(delta.total_seconds() * 1_000_000)
    conn.execute("INSERT INTO urls VALUES (1, 'https://darkpaste.example/x', "
                 "'exfil paste', 7, ?)", (webkit,))
    conn.commit()
    conn.close()


def _firefox_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT,
        title TEXT, visit_count INTEGER)""")
    conn.execute("""CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY,
        place_id INTEGER, visit_date INTEGER)""")
    conn.execute("INSERT INTO moz_places VALUES (1, 'https://tor.example', "
                 "'hidden wiki', 3)")
    conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1, 1784368800000000)")
    conn.commit()
    conn.close()


def test_parse_chrome_and_firefox(tmp_path):
    chrome = tmp_path / "History"
    firefox = tmp_path / "places.sqlite"
    _chrome_db(chrome)
    _firefox_db(firefox)

    cv = parse_chrome(chrome)
    assert len(cv) == 1 and cv[0].url == "https://darkpaste.example/x"
    assert cv[0].visited_at.startswith("2026-")

    fv = parse_firefox(firefox)
    assert len(fv) == 1 and fv[0].title == "hidden wiki"
    assert fv[0].visited_at == "2026-07-18T10:00:00Z"


# -- EXIF GPS -------------------------------------------------------------

def test_exif_gps_roundtrip(tmp_path):
    import piexif
    from PIL import Image

    photo = tmp_path / "scene.jpg"
    Image.new("RGB", (32, 32), (200, 60, 60)).save(photo)
    exif_bytes = piexif.dump({
        "0th": {piexif.ImageIFD.Make: b"Apple", piexif.ImageIFD.Model: b"iPhone XR"},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((51, 1), (30, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((0, 1), (7, 1), (3900, 100)),
        },
    })
    piexif.insert(exif_bytes, str(photo))

    meta = extract_exif(photo)
    assert meta is not None
    assert meta["model"] == "iPhone XR"
    assert abs(meta["lat"] - 51.5) < 0.001
    assert abs(meta["lon"] + 0.1275) < 0.001


def test_exif_none_for_plain_file(tmp_path):
    f = tmp_path / "not_image.jpg"
    f.write_bytes(b"junk")
    assert extract_exif(f) is None


# -- pipeline -------------------------------------------------------------

def test_scan_pipeline_and_hive_events(tmp_path):
    target = tmp_path / "mount"
    (target / "Users/jacob/AppData/Local/Google/Chrome/User Data/Default").mkdir(
        parents=True)
    _chrome_db(target / "Users/jacob/AppData/Local/Google/Chrome/User Data/Default/History")
    (target / "payload.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (target / "innocent.jpg").write_bytes(b"MZ" + b"\x00" * 64)  # masquerade
    (target / "note.txt").write_bytes(b"hello")

    result = scan(target)
    assert len(result.executables) == 2
    assert len(result.mismatches) == 1
    assert len(result.visits) == 1

    events = to_hive_events(result, device="Comb01")
    types = [e["event_type"] for e in events]
    assert types[0] == "analysis_started" and types[-1] == "analysis_completed"
    assert types.count("executable_found") == 2
    # A mismatched *executable* is reported once as executable_found, not twice
    assert types.count("artifact_mismatch") == 0
    assert "artifact_web_visit" in types
