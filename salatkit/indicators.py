from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import List

from salatkit.peutil import PeImage


@dataclass(frozen=True)
class Indicator:
    group: str
    needle: bytes


INDICATORS: List[Indicator] = [
    Indicator("lock bypass", b"NtQuerySystemInformation"),
    Indicator("lock bypass", b"DuplicateHandle"),
    Indicator("lock bypass", b"mode=ro"),
    Indicator("lock bypass", b"immutable"),
    Indicator("lock bypass", b"nolock"),
    Indicator("chromium", b"Local State"),
    Indicator("chromium", b"os_crypt"),
    Indicator("chromium", b"encrypted_key"),
    Indicator("chromium", b"app_bound_encrypted_key"),
    Indicator("chromium", b"Login Data"),
    Indicator("chromium", b"Web Data"),
    Indicator("chromium", b"Local Extension Settings"),
    Indicator("system token", b"failed to find LSASS process"),
    Indicator("system token", b"failed to impersonate SYSTEM"),
    Indicator("system token", b"DuplicateTokenEx"),
    Indicator("yandex", b"SELECT value FROM meta WHERE key = 'local_encryptor_data'"),
    Indicator("firefox", b"key4.db"),
    Indicator("firefox", b"nssPrivate"),
    Indicator("firefox", b"logins.json"),
    Indicator("discord", b"Tokens.txt"),
    Indicator("discord", b"leveldb"),
    Indicator("steam", b"config.vdf"),
    Indicator("steam", b"local.vdf"),
    Indicator("telegram", b"tdata"),
    Indicator("telegram", b"found tg process"),
    Indicator("input", b"Clipboard"),
    Indicator("input", b"Keylog"),
]


def scan(image: PeImage, limit: int = 3) -> List[str]:
    rows: List[str] = []
    for item in INDICATORS:
        start = 0
        hits: List[int] = []
        while len(hits) < limit:
            pos = image.data.find(item.needle, start)
            if pos < 0:
                break
            hits.append(pos)
            start = pos + 1
        shown = ", ".join(f"0x{image.va_of_offset(p):X}" for p in hits) or "not found"
        rows.append(f"{item.group:13s} {item.needle.decode('latin1'):58s} {shown}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage2", type=Path)
    args = parser.parse_args()
    for row in scan(PeImage.from_path(args.stage2)):
        print(row)


if __name__ == "__main__":
    main()
