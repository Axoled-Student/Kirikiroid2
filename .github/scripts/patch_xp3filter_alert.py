#!/usr/bin/env python3
"""
Bypass blocked iOS native dialogs and broken touch callbacks in the upstream IPA.

The IPA is prebuilt, so source changes alone do not affect the artifact produced
by this workflow. This script patches the arm64 Mach-O instruction that branches
into the specific native alert block which loads "archive_repack_no_xp3filter",
and patches the New Folder menu action to accept its default name without showing
the frozen native text prompt. It also patches the file-list click guard that
drops normal taps after iOS clears the long-press timer, and removes the native
delete confirmation path that freezes the app.
"""

from __future__ import annotations

import plistlib
import struct
import sys
from pathlib import Path


FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
NOP_ARM64 = b"\x1f\x20\x03\xd5"
MOV_W0_ZERO_ARM64 = b"\x00\x00\x80\x52"
XP3FILTER_KEY = b"archive_repack_no_xp3filter"
NEW_FOLDER_PROMPT = b"Input name"
DELETE_CONFIRM_KEY = b"ensure_to_delete_file"
FILE_ITEM_CSB = b"ui/FileItem.csb"


class PatchError(RuntimeError):
    pass


def read_u32be(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def read_u32le(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_u64le(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def resolve_executable(path: Path) -> Path:
    if path.is_file():
        return path
    if not path.is_dir() or path.suffix != ".app":
        raise PatchError(f"Expected an .app directory or executable file, got: {path}")

    plist_path = path / "Info.plist"
    if not plist_path.is_file():
        raise PatchError(f"Info.plist not found at: {plist_path}")
    with plist_path.open("rb") as plist_file:
        info = plistlib.load(plist_file)

    executable_name = info.get("CFBundleExecutable")
    if not executable_name:
        raise PatchError("CFBundleExecutable is missing from Info.plist")
    executable = path / executable_name
    if not executable.is_file():
        raise PatchError(f"Executable not found at: {executable}")
    return executable


def iter_slices(data: bytes | bytearray):
    magic = read_u32be(data, 0)
    if magic == FAT_MAGIC:
        count = read_u32be(data, 4)
        for index in range(count):
            offset = 8 + index * 20
            cpu_type = read_u32be(data, offset)
            slice_offset = read_u32be(data, offset + 8)
            slice_size = read_u32be(data, offset + 12)
            yield cpu_type, slice_offset, slice_size
        return

    if magic == FAT_MAGIC_64:
        count = read_u32be(data, 4)
        for index in range(count):
            offset = 8 + index * 32
            cpu_type = read_u32be(data, offset)
            slice_offset = struct.unpack_from(">Q", data, offset + 8)[0]
            slice_size = struct.unpack_from(">Q", data, offset + 16)[0]
            yield cpu_type, slice_offset, slice_size
        return

    yield read_u32le(data, 4), 0, len(data)


def parse_sections_64(data: bytes | bytearray, slice_offset: int):
    if read_u32le(data, slice_offset) != MH_MAGIC_64:
        raise PatchError("arm64 slice is not a 64-bit Mach-O image")

    command_count = read_u32le(data, slice_offset + 16)
    pos = slice_offset + 32
    sections = []

    for _ in range(command_count):
        cmd = read_u32le(data, pos)
        cmd_size = read_u32le(data, pos + 4)
        if cmd == LC_SEGMENT_64:
            segment_name = bytes(data[pos + 8 : pos + 24]).split(b"\0", 1)[0].decode("ascii", "ignore")
            section_count = read_u32le(data, pos + 64)
            section_pos = pos + 72
            for _ in range(section_count):
                section_name = bytes(data[section_pos : section_pos + 16]).split(b"\0", 1)[0].decode(
                    "ascii", "ignore"
                )
                address = read_u64le(data, section_pos + 32)
                size = read_u64le(data, section_pos + 40)
                file_offset = read_u32le(data, section_pos + 48)
                sections.append(
                    {
                        "name": section_name,
                        "segment": segment_name,
                        "address": address,
                        "size": size,
                        "file_offset": file_offset,
                    }
                )
                section_pos += 80
        pos += cmd_size

    return sections


def find_section(sections, name: str):
    for section in sections:
        if section["name"] == name:
            return section
    raise PatchError(f"Mach-O section not found: {name}")


def file_offset_to_vmaddr(sections, file_offset: int) -> int:
    for section in sections:
        start = section["file_offset"]
        end = start + section["size"]
        if start <= file_offset < end:
            return section["address"] + (file_offset - start)
    raise PatchError(f"Could not map file offset to VM address: 0x{file_offset:x}")


def vmaddr_to_file_offset(section, vmaddr: int) -> int:
    return section["file_offset"] + (vmaddr - section["address"])


def decode_adrp_target(instruction: int, pc: int):
    if instruction & 0x9F000000 != 0x90000000:
        return None
    rd = instruction & 0x1F
    immlo = (instruction >> 29) & 0x3
    immhi = (instruction >> 5) & 0x7FFFF
    immediate = sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + immediate


def is_add_same_register_immediate(instruction: int, register: int, immediate: int) -> bool:
    if instruction & 0xFFC00000 != 0x91000000:
        return False
    rd = instruction & 0x1F
    rn = (instruction >> 5) & 0x1F
    imm12 = (instruction >> 10) & 0xFFF
    shift = (instruction >> 22) & 0x1
    return rd == register and rn == register and imm12 == immediate and shift == 0


def decode_cbz_target(instruction: int, pc: int):
    # Ignore the 32/64-bit size bit, but require CBZ instead of CBNZ.
    if instruction & 0x7F000000 != 0x34000000:
        return None
    immediate = sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2
    register = instruction & 0x1F
    return register, pc + immediate


def find_alert_string_xrefs(data: bytes | bytearray, slice_offset: int, text_section, target_vmaddr: int):
    text_start = slice_offset + text_section["file_offset"]
    text_end = text_start + text_section["size"]
    text_vmaddr = text_section["address"]
    target_page = target_vmaddr & ~0xFFF
    target_page_offset = target_vmaddr & 0xFFF
    xrefs = []

    for file_offset in range(text_start, text_end - 4, 4):
        instruction = read_u32le(data, file_offset)
        pc = text_vmaddr + (file_offset - text_start)
        decoded = decode_adrp_target(instruction, pc)
        if not decoded:
            continue
        register, page = decoded
        if page != target_page:
            continue

        for next_offset in range(file_offset + 4, min(file_offset + 4 * 21, text_end - 4), 4):
            next_instruction = read_u32le(data, next_offset)
            if is_add_same_register_immediate(next_instruction, register, target_page_offset):
                xrefs.append(pc)
                break

    return xrefs


def find_adjacent_string_xrefs(data: bytes | bytearray, slice_offset: int, text_section, target_vmaddr: int):
    text_start = slice_offset + text_section["file_offset"]
    text_end = text_start + text_section["size"]
    text_vmaddr = text_section["address"]
    target_page = target_vmaddr & ~0xFFF
    target_page_offset = target_vmaddr & 0xFFF
    xrefs = []

    for file_offset in range(text_start, text_end - 8, 4):
        instruction = read_u32le(data, file_offset)
        pc = text_vmaddr + (file_offset - text_start)
        decoded = decode_adrp_target(instruction, pc)
        if not decoded:
            continue
        register, page = decoded
        if page != target_page:
            continue
        next_instruction = read_u32le(data, file_offset + 4)
        if is_add_same_register_immediate(next_instruction, register, target_page_offset):
            xrefs.append(pc)

    return xrefs


def find_alert_entry_branch(data: bytes | bytearray, slice_offset: int, text_section, xref_vmaddr: int):
    text_start = slice_offset + text_section["file_offset"]
    text_vmaddr = text_section["address"]
    xref_file_offset = text_start + (xref_vmaddr - text_vmaddr)
    search_start = max(text_start, xref_file_offset - 0x200)

    candidates = []
    for file_offset in range(search_start, xref_file_offset, 4):
        instruction = read_u32le(data, file_offset)
        pc = text_vmaddr + (file_offset - text_start)
        decoded = decode_cbz_target(instruction, pc)
        if not decoded:
            continue
        _, target = decoded
        if target <= xref_vmaddr <= target + 0x80:
            candidates.append((file_offset, pc, target))

    if len(candidates) != 1:
        already_patched = []
        for file_offset in range(search_start, xref_file_offset, 4):
            pc = text_vmaddr + (file_offset - text_start)
            if bytes(data[file_offset : file_offset + 4]) == NOP_ARM64 and 0x40 <= xref_vmaddr - pc <= 0x120:
                already_patched.append((file_offset, pc, None))

        exact_already_patched = [
            candidate for candidate in already_patched if xref_vmaddr - candidate[1] == 0x84
        ]
        if len(exact_already_patched) == 1:
            return exact_already_patched[0]
        if len(already_patched) == 1:
            return already_patched[0]

        details = ", ".join(f"0x{pc:x}->0x{target:x}" for _, pc, target in candidates) or "none"
        raise PatchError(f"Expected one CBZ into xp3filter alert block near 0x{xref_vmaddr:x}; found {details}")

    return candidates[0]


def patch_xp3filter_alert(data: bytearray, slice_offset: int, slice_size: int, sections, text_section) -> bool:
    key_offset = bytes(data).find(XP3FILTER_KEY, slice_offset, slice_offset + slice_size)
    if key_offset < 0:
        raise PatchError("xp3filter alert locale key not found in arm64 slice")

    key_slice_offset = key_offset - slice_offset
    key_vmaddr = file_offset_to_vmaddr(sections, key_slice_offset)
    xrefs = find_alert_string_xrefs(data, slice_offset, text_section, key_vmaddr)
    if len(xrefs) != 1:
        details = ", ".join(f"0x{xref:x}" for xref in xrefs) or "none"
        raise PatchError(f"Expected one xref to xp3filter alert key; found {details}")

    branch_file_offset, branch_vmaddr, target_vmaddr = find_alert_entry_branch(
        data, slice_offset, text_section, xrefs[0]
    )

    existing = bytes(data[branch_file_offset : branch_file_offset + 4])
    if existing == NOP_ARM64:
        print(f"arm64 xp3filter alert branch already patched at 0x{branch_vmaddr:x}")
        return False

    data[branch_file_offset : branch_file_offset + 4] = NOP_ARM64
    target_text = f" targeting 0x{target_vmaddr:x}" if target_vmaddr is not None else ""
    print(f"Patched arm64 xp3filter alert branch at 0x{branch_vmaddr:x}{target_text}")
    return True


def patch_new_folder_input(data: bytearray, slice_offset: int, slice_size: int, sections, text_section) -> bool:
    prompt_offset = bytes(data).find(NEW_FOLDER_PROMPT, slice_offset, slice_offset + slice_size)
    if prompt_offset < 0:
        raise PatchError("New Folder input prompt string not found in arm64 slice")

    prompt_slice_offset = prompt_offset - slice_offset
    prompt_vmaddr = file_offset_to_vmaddr(sections, prompt_slice_offset)
    xrefs = find_adjacent_string_xrefs(data, slice_offset, text_section, prompt_vmaddr)
    if len(xrefs) != 1:
        details = ", ".join(f"0x{xref:x}" for xref in xrefs) or "none"
        raise PatchError(f"Expected one exact xref to New Folder input prompt; found {details}")

    text_start = slice_offset + text_section["file_offset"]
    text_vmaddr = text_section["address"]
    xref_file_offset = text_start + (xrefs[0] - text_vmaddr)
    search_end = min(text_start + text_section["size"] - 8, xref_file_offset + 0x80)

    candidates = []
    already_patched = []
    for file_offset in range(xref_file_offset, search_end, 4):
        instruction = read_u32le(data, file_offset)
        next_instruction = read_u32le(data, file_offset + 4)
        pc = text_vmaddr + (file_offset - text_start)

        if bytes(data[file_offset : file_offset + 4]) == MOV_W0_ZERO_ARM64 and next_instruction == 0xAA0003F4:
            already_patched.append((file_offset, pc))
        elif instruction & 0xFC000000 == 0x94000000 and next_instruction == 0xAA0003F4:
            candidates.append((file_offset, pc))

    if not candidates and len(already_patched) == 1:
        _, pc = already_patched[0]
        print(f"arm64 New Folder native input already patched at 0x{pc:x}")
        return False

    if len(candidates) != 1:
        details = ", ".join(f"0x{pc:x}" for _, pc in candidates) or "none"
        raise PatchError(f"Expected one New Folder input call to patch; found {details}")

    call_file_offset, call_vmaddr = candidates[0]
    data[call_file_offset : call_file_offset + 4] = MOV_W0_ZERO_ARM64
    print(f"Patched arm64 New Folder native input call at 0x{call_vmaddr:x}")
    return True


def patch_file_item_click_guard(data: bytearray, slice_offset: int, slice_size: int, sections, text_section) -> bool:
    file_item_offset = bytes(data).find(FILE_ITEM_CSB, slice_offset, slice_offset + slice_size)
    if file_item_offset < 0:
        raise PatchError("FileItem CSB path string not found in arm64 slice")

    file_item_slice_offset = file_item_offset - slice_offset
    file_item_vmaddr = file_offset_to_vmaddr(sections, file_item_slice_offset)
    xrefs = find_adjacent_string_xrefs(data, slice_offset, text_section, file_item_vmaddr)
    if len(xrefs) != 1:
        details = ", ".join(f"0x{xref:x}" for xref in xrefs) or "none"
        raise PatchError(f"Expected one exact xref to FileItem CSB path; found {details}")

    text_start = slice_offset + text_section["file_offset"]
    text_vmaddr = text_section["address"]
    search_start = text_start + (xrefs[0] - text_vmaddr)
    search_end = min(text_start + text_section["size"] - 8, search_start + 0x2500)

    candidates = []
    already_patched = []
    for file_offset in range(search_start, search_end, 4):
        pc = text_vmaddr + (file_offset - text_start)
        previous_instruction = read_u32le(data, file_offset - 4)
        next_instruction = read_u32le(data, file_offset + 4)

        if previous_instruction & 0xFC000000 != 0x94000000:
            continue
        if not decode_adrp_target(next_instruction, pc + 4):
            continue

        existing = bytes(data[file_offset : file_offset + 4])
        if existing == NOP_ARM64:
            already_patched.append((file_offset, pc))
            continue

        decoded = decode_cbz_target(read_u32le(data, file_offset), pc)
        if not decoded:
            continue
        register, target = decoded
        if register == 0 and target == pc + 0x34:
            candidates.append((file_offset, pc, target))

    if not candidates and len(already_patched) == 1:
        _, pc = already_patched[0]
        print(f"arm64 FileItem click guard already patched at 0x{pc:x}")
        return False

    if len(candidates) != 1:
        details = ", ".join(f"0x{pc:x}->0x{target:x}" for _, pc, target in candidates) or "none"
        raise PatchError(f"Expected one FileItem click guard to patch; found {details}")

    guard_file_offset, guard_vmaddr, target_vmaddr = candidates[0]
    data[guard_file_offset : guard_file_offset + 4] = NOP_ARM64
    print(f"Patched arm64 FileItem click guard at 0x{guard_vmaddr:x} targeting 0x{target_vmaddr:x}")
    return True


def patch_delete_confirmation(data: bytearray, slice_offset: int, slice_size: int, sections, text_section) -> bool:
    key_offset = bytes(data).find(DELETE_CONFIRM_KEY, slice_offset, slice_offset + slice_size)
    if key_offset < 0:
        raise PatchError("delete confirmation locale key not found in arm64 slice")

    key_slice_offset = key_offset - slice_offset
    key_vmaddr = file_offset_to_vmaddr(sections, key_slice_offset)
    xrefs = find_adjacent_string_xrefs(data, slice_offset, text_section, key_vmaddr)
    if len(xrefs) != 1:
        details = ", ".join(f"0x{xref:x}" for xref in xrefs) or "none"
        raise PatchError(f"Expected one exact xref to delete confirmation key; found {details}")

    text_start = slice_offset + text_section["file_offset"]
    text_vmaddr = text_section["address"]
    xref_file_offset = text_start + (xrefs[0] - text_vmaddr)
    search_end = min(text_start + text_section["size"] - 8, xref_file_offset + 0x120)

    candidates = []
    already_patched = []
    for file_offset in range(xref_file_offset, search_end, 4):
        pc = text_vmaddr + (file_offset - text_start)
        instruction = read_u32le(data, file_offset)
        next_instruction = read_u32le(data, file_offset + 4)

        if next_instruction != 0xAA0003F4:  # mov x20, x0
            continue
        if bytes(data[file_offset : file_offset + 4]) == MOV_W0_ZERO_ARM64:
            already_patched.append((file_offset, pc))
        elif instruction & 0xFC000000 == 0x94000000:
            candidates.append((file_offset, pc))

    if not candidates and len(already_patched) == 1:
        _, pc = already_patched[0]
        print(f"arm64 delete native confirmation already patched at 0x{pc:x}")
        return False

    if len(candidates) != 1:
        details = ", ".join(f"0x{pc:x}" for _, pc in candidates) or "none"
        raise PatchError(f"Expected one delete confirmation call to patch; found {details}")

    call_file_offset, call_vmaddr = candidates[0]
    data[call_file_offset : call_file_offset + 4] = MOV_W0_ZERO_ARM64
    print(f"Patched arm64 delete native confirmation call at 0x{call_vmaddr:x}")
    return True


def patch_arm64_slice(data: bytearray, slice_offset: int, slice_size: int) -> bool:
    sections = parse_sections_64(data, slice_offset)
    text_section = find_section(sections, "__text")

    patched = False
    patched = patch_xp3filter_alert(data, slice_offset, slice_size, sections, text_section) or patched
    patched = patch_new_folder_input(data, slice_offset, slice_size, sections, text_section) or patched
    patched = patch_file_item_click_guard(data, slice_offset, slice_size, sections, text_section) or patched
    patched = patch_delete_confirmation(data, slice_offset, slice_size, sections, text_section) or patched
    return patched


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} <App.app|Mach-O executable>", file=sys.stderr)
        return 2

    executable = resolve_executable(Path(sys.argv[1]))
    data = bytearray(executable.read_bytes())

    patched = False
    arm64_seen = False
    for cpu_type, slice_offset, slice_size in iter_slices(data):
        if cpu_type != CPU_TYPE_ARM64:
            continue
        arm64_seen = True
        patched = patch_arm64_slice(data, slice_offset, slice_size) or patched

    if not arm64_seen:
        raise PatchError("No arm64 Mach-O slice found")

    if patched:
        executable.write_bytes(data)
    else:
        print("No binary changes were needed.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
