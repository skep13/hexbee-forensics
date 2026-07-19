"""HexBee Comb — the analysis cell of the hive.

Queen-side forensic triage toolkit in the spirit of Autopsy / Magnet AXIOM,
with HexBee's twist: everything it finds can be pushed into the Hive's
hash-chained evidence log, so analysis artifacts get the same
chain-of-custody treatment as live Scout acquisitions.

Capabilities:
    - file inventory: SHA-256, magic-byte identification, extension-mismatch
      detection, MAC timestamps
    - signature-based file carving from raw disk images
    - MBR/GPT partition table parsing (pure Python), with automatic
      Sleuth Kit (mmls/fls) integration when installed (Kali ships it)
    - EXIF metadata + GPS extraction from images (feeds the Hive's offline
      evidence map)
    - browser history parsing (Chrome/Chromium, Firefox)
    - unified analysis timeline + branded HTML report
"""

__version__ = "0.1.0"
