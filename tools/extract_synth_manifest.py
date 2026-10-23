#!/usr/bin/env python3
"""Extracts the frozen synthetic-module manifest from the host's real DLLs.

Dev-time tool (run on a Windows host, committed output): for each Tier 1
module and architecture it walks the real DLL's export table and records
{name, ordinal} per export, the syscall number encoded in each Nt* stub,
and the x86 stdcall cleanup byte count parsed from the real function bodies.
The manifest is committed and becomes the only input of the build-time
generator (see gen_synth_modules.py) - builds never read host DLLs.
"""
import json
import struct
import sys
from pathlib import Path

TIER1 = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll",
         "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"]

# canonical Win10+ x64 ntdll syscall stub prefix: mov r10, rcx; mov eax, imm32
X64_STUB_PREFIX = b"\x4c\x8b\xd1\xb8"
# x86 wow64 syscall stub: mov eax, imm32; mov edx, transition; call edx
X86_STUB_MAGIC = (0xB8, 0xBA, 0xFF, 0xD2)


def read_cstr(data, rva, limit=256):
    end = data.index(b"\0", min(rva, len(data) - 1))
    return data[rva:end].decode("ascii", errors="replace")[:limit]


def parse_exports(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine, num_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    opt = e_lfanew + 0x18
    exp_rva = struct.unpack_from("<I", data, opt + (0x70 if magic == 0x20B else 0x60))[0]
    if exp_rva == 0:
        return machine, []
    # section table maps RVAs to file offsets
    sec_table = opt + (0xF0 if magic == 0x20B else 0xE0)
    sections = []
    for i in range(num_sections):
        off = sec_table + i * 40
        # header: Name[8], VirtualSize@+8, VirtualAddress@+12,
        # SizeOfRawData@+16, PointerToRawData@+20
        vrva, rsize, roff = struct.unpack_from("<III", data, off + 12)
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        sections.append((vrva, max(vsize, rsize), roff))
    def rva2off(rva):
        for vrva, span, roff in sections:
            if vrva <= rva < vrva + span:
                return rva - vrva + roff
        raise ValueError("rva %x not in any section" % rva)

    eo = rva2off(exp_rva)
    export_base = struct.unpack_from("<I", data, eo + 0x10)[0]
    names_count = struct.unpack_from("<I", data, eo + 0x18)[0]
    addr_rva, names_rva, ords_rva = struct.unpack_from("<III", data, eo + 0x1C)
    addr_off, names_off, ords_off = rva2off(addr_rva), rva2off(names_rva), rva2off(ords_rva)
    exports = []
    for i in range(names_count):
        name_rva = struct.unpack_from("<I", data, names_off + 4 * i)[0]
        ordinal = struct.unpack_from("<H", data, ords_off + 2 * i)[0] + export_base
        func_rva = struct.unpack_from("<I", data, addr_off + 4 * (ordinal - export_base))[0]
        name = read_cstr(data, rva2off(name_rva))
        entry = {"name": name, "ordinal": ordinal}
        if func_rva == 0:
            exports.append(entry)  # forwarded or empty export: no local body
            continue
        body_off = rva2off(func_rva)
        body = data[body_off:body_off + 32]
        if machine == 0x8664:
            if body[:4] == X64_STUB_PREFIX:
                entry["syscall_number"] = struct.unpack_from("<I", body, 4)[0]
        else:
            if (body[0] == X86_STUB_MAGIC[0] and body[5] == X86_STUB_MAGIC[1] and
                    body[10] == X86_STUB_MAGIC[2] and body[11] == X86_STUB_MAGIC[3]):
                entry["syscall_number"] = struct.unpack_from("<I", body, 1)[0]
            elif body[0] == 0xC3:
                entry["stdcall_cleanup"] = 0
            elif body[0] == 0xC2:
                entry["stdcall_cleanup"] = struct.unpack_from("<H", body, 1)[0]
        exports.append(entry)
    return machine, sorted(exports, key=lambda e: e["ordinal"])


def main():
    if len(sys.argv) != 2:
        print("usage: extract_synth_manifest.py <output-dir>")
        return 1
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
    system_root = Path(buf.value)
    ctypes.windll.kernel32.GetSystemWow64DirectoryW(buf, 260)
    wow64_root = Path(buf.value)
    for arch, root in (("x64", system_root), ("x86", wow64_root)):
        for module in TIER1:
            dll = root / module
            if not dll.exists():
                print("skip (not present on host):", dll)
                continue
            data = dll.read_bytes()
            machine, exports = parse_exports(data)
            manifest = {
                "name": module,
                "arch": arch,
                "machine": hex(machine),
                "export_count": len(exports),
                "exports": exports,
            }
            out = out_dir / ("%s.%s.json" % (module[:-4], arch))
            out.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
            print("%s: %d exports" % (out, len(exports)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
