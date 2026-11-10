from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    vsize: int
    raw_off: int
    raw_size: int

    def contains_rva(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + max(self.vsize, self.raw_size)


class PeImage:
    def __init__(self, data: bytes) -> None:
        if data[:2] != b"MZ":
            raise ValueError("no MZ signature")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("no PE signature")
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        if machine != 0x14C:
            raise ValueError(f"only x86 PE32 is supported, machine=0x{machine:X}")
        n_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        self.data: bytes = data
        self.image_base: int = struct.unpack_from("<I", data, e_lfanew + 24 + 28)[0]
        self.sections: List[Section] = []
        table = e_lfanew + 24 + opt_size
        for i in range(n_sections):
            raw_name, vsize, rva, raw_size, raw_off = struct.unpack_from("<8sIIII", data, table + 40 * i)
            self.sections.append(Section(raw_name.rstrip(b"\x00").decode("latin1"), rva, vsize, raw_off, raw_size))

    @classmethod
    def from_path(cls, path: str | Path) -> "PeImage":
        return cls(Path(path).read_bytes())

    def section(self, name: str) -> Section:
        for sec in self.sections:
            if sec.name == name:
                return sec
        raise KeyError(name)

    def offset_of(self, va: int) -> int:
        rva = va - self.image_base
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec.raw_off + (rva - sec.rva)
        raise ValueError(f"address 0x{va:X} is outside sections")

    def read(self, va: int, size: int) -> bytes:
        off = self.offset_of(va)
        return self.data[off:off + size]
