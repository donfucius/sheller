#!/usr/bin/env python3
"""Generates the deterministic synthetic system modules from the frozen
manifests (build-time; outputs are never committed).

Each manifest produces a minimal PE whose export table carries the frozen
names + ordinals and whose code is deterministic stubs:
  - x64 Nt* export: 4C 8B D1 B8 <num32> 0F 05 C3 (the canonical Win10+ ntdll
    syscall stub shape the engine's number parser matches)
  - x86 Nt* export: B8 <num32> BA <transition32> FF D2 (the wow64 shape)
  - everything else: xor eax, eax [+ stdcall cleanup from the manifest]
ntdll additionally welds a .data section at the fixed RVA 0x41000
(SYNTH_WOW64_TRANSITION_RVA) where the engine writes its transition pointer.
Same manifest in, byte-identical output out.
"""
import json
import struct
import sys
from pathlib import Path

SECTION_RVA = 0x1000
SECTION_FILE_OFF = 0x1000
STUB_STRIDE = 16
NTDLL_TEXT_SPAN = 0x40000          # ntdll payload padded to this span
SYNTH_DATA_RVA = SECTION_RVA + NTDLL_TEXT_SPAN  # 0x41000: welded data slots
SYNTH_WOW64_TRANSITION_RVA = SYNTH_DATA_RVA  # engine double-writes this constant
X86_WOW64_TRANSITION = 0x7FFD0000 + 0x30  # the int2e stub inside the engine's page

X64_STUB_HEAD = b"\x4c\x8b\xd1\xb8"  # mov r10, rcx; mov eax, imm32
X64_STUB_TAIL = b"\x0f\x05\xc3"      # syscall; ret
X86_STUB_TAIL = b"\xba" + struct.pack("<I", X86_WOW64_TRANSITION) + b"\xff\xd2"


def emit_module(manifest):
    x86 = manifest["arch"] == "x86"
    machine = 0x014C if x86 else 0x8664
    magic = 0x010B if x86 else 0x020B
    opt_header_size = 0xE0 if x86 else 0xF0
    is_ntdll = manifest["name"] == "ntdll.dll"
    exports = manifest["exports"]

    stubs = b""
    stub_rvas = []
    cursor = SECTION_RVA
    for entry in exports:
        stub_rvas.append(cursor)
        if entry["name"][:2] == "Nt" and "syscall_number" in entry:
            if x86:
                body = (b"\xb8" + struct.pack("<I", entry["syscall_number"]) +
                        X86_STUB_TAIL)
            else:
                body = (X64_STUB_HEAD + struct.pack("<I", entry["syscall_number"]) +
                        X64_STUB_TAIL)
        else:
            body = b"\x31\xc0"  # xor eax, eax
            if x86:
                body += b"\xc2" + struct.pack("<H", entry.get("stdcall_cleanup", 0))
        stubs += body + b"\x90" * (STUB_STRIDE - len(body))
        cursor += STUB_STRIDE
    assert not is_ntdll or cursor - SECTION_RVA <= NTDLL_TEXT_SPAN, \
        "ntdll stub area overflow"

    export_base = min(e["ordinal"] for e in exports)
    max_ordinal = max(e["ordinal"] for e in exports)
    rva_by_ordinal = {e["ordinal"]: stub_rvas[i] for i, e in enumerate(exports)}
    eat = b"".join(struct.pack("<I", rva_by_ordinal.get(o, 0))
                   for o in range(export_base, max_ordinal + 1))
    named = sorted(exports, key=lambda e: e["name"])
    name_offsets = []
    off = 0
    for e in named:
        name_offsets.append(off)
        off += len(e["name"]) + 1
    ordinals = b"".join(struct.pack("<H", e["ordinal"] - export_base) for e in named)
    module_name = manifest["name"].encode("ascii") + b"\0"
    name_bytes = b"".join(e["name"].encode("ascii") + b"\0" for e in named)

    export_dir_rva = cursor
    export_functions_rva = export_dir_rva + 40
    export_names_rva = export_functions_rva + len(eat)
    export_ordinals_rva = export_names_rva + 4 * len(named)
    export_name_rva = export_ordinals_rva + 2 * len(named)
    name_strings_rva = export_name_rva + len(module_name)
    cursor = name_strings_rva + len(name_bytes)
    # IMAGE_EXPORT_DIRECTORY (40 bytes): ..., Name, Base, NumberOfFunctions,
    # NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
    directory = struct.pack("<IIHHIIIIIII",
                            0,               # characteristics
                            0,               # timestamp
                            0, 0,            # version
                            export_name_rva,
                            export_base,
                            max_ordinal - export_base + 1,
                            len(named),
                            export_functions_rva,
                            export_names_rva,
                            export_ordinals_rva)
    names = b"".join(struct.pack("<I", name_strings_rva + o) for o in name_offsets)
    payload = stubs + directory + eat + names + ordinals + module_name + name_bytes
    if is_ntdll:
        payload += b"\x00" * (NTDLL_TEXT_SPAN - len(payload))

    sections = [(b".text", len(payload), SECTION_RVA, len(payload),
                 SECTION_FILE_OFF, 0x60000020)]
    raw = payload
    if is_ntdll:
        sections.append((b".data", 0x200, SYNTH_DATA_RVA, 0x200,
                         SECTION_FILE_OFF + len(payload), 0xC0000040))
        raw += b"\x00" * 0x200

    file_header = bytearray(0x14)
    struct.pack_into("<HHIIIHH", file_header, 0, machine,
                     len(sections), 0, 0, 0, opt_header_size, 0x2022)

    opt = bytearray(opt_header_size)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<I", opt, 4, sum(s[3] for s in sections))  # SizeOfCode
    struct.pack_into("<I", opt, 16, SECTION_RVA)            # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, SECTION_RVA)            # BaseOfCode
    if x86:
        struct.pack_into("<I", opt, 28, 0x400000)           # ImageBase (pe32)
        number_of_rvas, data_dir = 92, 96
    else:
        struct.pack_into("<Q", opt, 24, 0x400000)           # ImageBase (pe32+)
        number_of_rvas, data_dir = 108, 112
    struct.pack_into("<I", opt, 32, 0x1000)                 # SectionAlignment
    struct.pack_into("<I", opt, 36, SECTION_FILE_OFF)       # FileAlignment
    struct.pack_into("<I", opt, 56, SYNTH_DATA_RVA + 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, SECTION_FILE_OFF)       # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)                      # SubSystem console
    struct.pack_into("<I", opt, number_of_rvas, 16)         # NumberOfRvaAndSizes
    export_dir_size = 40 + len(eat) + len(names) + len(ordinals) + len(module_name) + len(name_bytes)
    struct.pack_into("<II", opt, data_dir, export_dir_rva, export_dir_size)

    table = b""
    for name, vsize, vrva, rsize, roff, chars in sections:
        entry = bytearray(40)
        entry[0:len(name)] = name
        struct.pack_into("<IIII", entry, 8, vsize, vrva, rsize, roff)
        struct.pack_into("<I", entry, 36, chars)
        table += entry

    head = bytearray(0x7C)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x7C)
    # pad the headers so the section raw data lands at SECTION_FILE_OFF
    header_bytes = 0x7C + 4 + 0x14 + opt_header_size + len(table)
    padding = b"\x00" * (SECTION_FILE_OFF - header_bytes)
    return bytes(head) + b"PE\0\0" + bytes(file_header) + bytes(opt) + table + padding + raw


def main():
    if len(sys.argv) != 3:
        print("usage: gen_synth_modules.py <manifest-dir> <out-dir>")
        return 1
    manifest_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    for manifest_path in sorted(manifest_dir.glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        image = emit_module(manifest)
        out = out_dir / ("%s.%s.dll" % (manifest["name"][:-4], manifest["arch"]))
        out.write_bytes(image)
        print("%s: %d bytes" % (out, len(image)))
    (out_dir / ".generated").write_bytes(b"ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
