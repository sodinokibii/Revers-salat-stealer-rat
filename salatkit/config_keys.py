from __future__ import annotations

import argparse
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from salatkit.peutil import PeImage


@dataclass(frozen=True)
class SealedKey:
    first_byte: int
    dwords: Tuple[int, ...]
    tail_hex: str


SEALED_KEY = SealedKey(
    first_byte=0xD8,
    dwords=(-2143288327, 1174663197, -29158311, 93989476, -1143011619, -739294564,
            -1606817187, 270982989, -1406026612, 797636959, 1475298340, 1916586150),
    tail_hex="fc9436c717",
)
AES_SEED = b"biba"
CERT_BLOB_VA = 0x9EC926


def prefix_xor(data: bytes) -> bytes:
    out = bytearray(data)
    for k in range(1, len(out)):
        out[k] ^= out[k - 1]
    return bytes(out)


def xor_cycle(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def derive_aes_key() -> bytes:
    return prefix_xor(hashlib.md5(AES_SEED).digest())


def derive_xor_key(aes_key: bytes) -> bytes:
    body = bytes([SEALED_KEY.first_byte]) + b"".join(struct.pack("<i", d) for d in SEALED_KEY.dwords)
    sealed = body + bytes.fromhex(SEALED_KEY.tail_hex)
    return AESGCM(aes_key).decrypt(sealed[:12], sealed[12:], None)


def open_sealed(hex_text: bytes, aes_key: bytes) -> bytes:
    sealed = bytes.fromhex(hex_text.decode("ascii"))
    return AESGCM(aes_key).decrypt(sealed[:12], sealed[12:], None)


def decrypt_entry(hex_text: bytes, aes_key: bytes, xor_key: bytes) -> bytes:
    layer = xor_cycle(prefix_xor(bytes.fromhex(hex_text.decode("ascii"))), xor_key)
    return open_sealed(layer, aes_key)


def extract_cert_bundle(image: PeImage, aes_key: bytes, xor_key: bytes) -> bytes:
    offset = image.offset_of(CERT_BLOB_VA)
    match = re.match(rb"[0-9a-f]+", image.data[offset:offset + 700_000])
    if match is None or len(match.group(0)) % 2:
        raise ValueError("no valid hex string at CERT_BLOB_VA")
    blob = bytes.fromhex(match.group(0).decode("ascii"))
    return open_sealed(xor_cycle(prefix_xor(blob), xor_key), aes_key)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage2", type=Path)
    parser.add_argument("--out-certs", type=Path)
    args = parser.parse_args()
    aes_key = derive_aes_key()
    try:
        xor_key = derive_xor_key(aes_key)
    except InvalidTag:
        raise SystemExit("aes-gcm tag mismatch, check SEALED_KEY and AES_SEED")
    print(f"aes-128 key: {aes_key.hex()}")
    print(f"xor key ({len(xor_key)} bytes): {xor_key.hex()}")
    bundle = extract_cert_bundle(PeImage.from_path(args.stage2), aes_key, xor_key)
    print(f"bundle: {len(bundle)} bytes, certificates: {bundle.count(b'-----BEGIN CERTIFICATE-----')}")
    if args.out_certs:
        args.out_certs.write_bytes(bundle)


if __name__ == "__main__":
    main()
