from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import List, Tuple

from salatkit.peutil import PeImage
from salatkit.config_keys import decrypt_entry, derive_aes_key, derive_xor_key

MODULUS_TABLE_VA = 0xC6A158
ENDPOINT_TABLE_VAS: Tuple[int, ...] = (0xC6A764, 0xC6A968, 0xC6AB6C)
PUBLIC_EXPONENT = 0x10001
TABLE_WORDS = 129
MODULUS_HEADER = 0xA5A5A7A5
LENGTH_MASK = 0xA5A5A5A5
GOLDEN = 0x9E3779B9


def rol32(value: int, count: int) -> int:
    count %= 32
    if not count:
        return value
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def read_table(image: PeImage, va: int) -> List[int]:
    return list(struct.unpack(f"<{TABLE_WORDS}I", image.read(va, TABLE_WORDS * 4)))


def table_to_int(words: List[int]) -> int:
    length = words[0] ^ LENGTH_MASK
    out = bytearray()
    for i in range(TABLE_WORDS - 1):
        mixed = ((4 * i) & 0xFFFFFFFF) ^ rol32(words[i + 1], (-4 * i) % 32)
        out += struct.pack(">I", (mixed ^ GOLDEN) & 0xFFFFFFFF)
    return int.from_bytes(bytes(out[len(out) - length:]), "big")


def recover_endpoints(image: PeImage) -> List[str]:
    modulus_words = read_table(image, MODULUS_TABLE_VA)
    modulus_words[0] = MODULUS_HEADER
    modulus = table_to_int(modulus_words)
    aes_key = derive_aes_key()
    xor_key = derive_xor_key(aes_key)
    result: List[str] = []
    for va in ENDPOINT_TABLE_VAS:
        value = pow(table_to_int(read_table(image, va)), PUBLIC_EXPONENT, modulus)
        text = value.to_bytes((value.bit_length() + 7) // 8, "big")
        result.append(decrypt_entry(text, aes_key, xor_key).decode("utf-8"))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage2", type=Path)
    args = parser.parse_args()
    for url in recover_endpoints(PeImage.from_path(args.stage2)):
        print(url)


if __name__ == "__main__":
    main()
