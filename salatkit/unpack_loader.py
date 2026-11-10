from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from salatkit.peutil import PeImage


@dataclass(frozen=True)
class LoaderParams:
    key_dwords: Tuple[int, ...]
    blob_va: int
    blob_len: int
    chain_seed: int
    chain_mask: int
    expected_size: int


KNOWN_SAMPLES: Dict[str, LoaderParams] = {
    "83d2faf575026b3f75446a6337f004f5d81e66d5e2bfa19c44c6ef369fd1ec1a": LoaderParams(
        key_dwords=(1095243335, 1209223192, 1292966466, 420694805,
                    1309888021, 1212291651, 474304021, 1226185542),
        blob_va=0x6304C0,
        blob_len=0x4BDB15,
        chain_seed=75,
        chain_mask=0x68,
        expected_size=0xBBD400,
    ),
}


def derive_rc4_key(params: LoaderParams) -> bytes:
    raw = b"".join(struct.pack("<I", d) for d in params.key_dwords)
    prev = params.chain_seed
    decoded = bytearray()
    for cipher_byte in raw:
        decoded.append(cipher_byte ^ prev ^ params.chain_mask)
        prev = cipher_byte
    try:
        return bytes.fromhex(decoded.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("chained xor result is not a hex string") from exc


def rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[n] = byte ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


def unpack(image: PeImage, params: LoaderParams) -> bytes:
    key = derive_rc4_key(params)
    plain = rc4(key, image.read(params.blob_va, params.blob_len))
    if plain[:1] != b"\x78":
        raise ValueError("no zlib header after rc4, wrong params")
    stage2 = zlib.decompress(plain)
    if len(stage2) != params.expected_size:
        raise ValueError(f"size {len(stage2)} differs from expected {params.expected_size}")
    return stage2


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("loader", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.loader.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    params = KNOWN_SAMPLES.get(digest)
    if params is None:
        raise SystemExit(f"unknown sample {digest}, add LoaderParams to KNOWN_SAMPLES")
    stage2 = unpack(PeImage(data), params)
    args.output.write_bytes(stage2)
    print(f"rc4 key: {derive_rc4_key(params).hex()}")
    print(f"size: {len(stage2)} sha256: {hashlib.sha256(stage2).hexdigest()}")


if __name__ == "__main__":
    main()
