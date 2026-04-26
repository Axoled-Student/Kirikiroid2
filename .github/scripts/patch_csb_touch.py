#!/usr/bin/env python3
"""Patch Cocos Studio .csb popup backgrounds so they do not consume button taps."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


PATCHES = {
    "ui/SelectList.csb": {
        "Panel_4",
        "Panel_5",
        "Panel_2_9_8",
        "Panel_2_0_11_10",
        "Panel_2_9_8_13",
        "Panel_2_0_11_10_15",
    },
    "ui/TextPairInput.csb": {
        "Panel_4",
        "Panel_13",
        "Panel_14",
    },
    "ui/BottomBarTextInput.csb": {
        "Panel_4",
        "Panel_14_9",
    },
    "ui/MessageBox.csb": {
        "Panel_1",
        "Panel_2",
        "Panel_6",
        "Panel_3",
        "btnList",
        "btn",
        "Panel_7",
    },
    "ui/CheckListDialog.csb": {
        "Panel_20",
        "Panel_1",
        "Panel_2",
        "Panel_4",
        "Panel_5",
        "btn_cell",
        "Panel_7",
    },
    "ui/comctrl/CheckBoxItem.csb": {
        "Panel_5",
    },
}


def u16(buf: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", buf, offset)[0]


def i32(buf: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<i", buf, offset)[0]


def u32(buf: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def table_field(buf: bytes | bytearray, table: int | None, voffset: int) -> int | None:
    if table is None or table < 0 or table + 4 > len(buf):
        return None
    vtable = table - i32(buf, table)
    if vtable < 0 or vtable + 4 > len(buf):
        return None
    vtable_size = u16(buf, vtable)
    if voffset >= vtable_size or vtable + voffset + 2 > len(buf):
        return None
    field_offset = u16(buf, vtable + voffset)
    if field_offset == 0:
        return None
    field = table + field_offset
    return field if 0 <= field < len(buf) else None


def ptr_field(buf: bytes | bytearray, table: int | None, voffset: int) -> int | None:
    field = table_field(buf, table, voffset)
    if field is None or field + 4 > len(buf):
        return None
    ptr = field + u32(buf, field)
    return ptr if 0 <= ptr < len(buf) else None


def string_at(buf: bytes | bytearray, ptr: int | None) -> str | None:
    if ptr is None or ptr + 4 > len(buf):
        return None
    size = u32(buf, ptr)
    if size > 1000 or ptr + 4 + size > len(buf):
        return None
    raw = bytes(buf[ptr + 4 : ptr + 4 + size])
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 32 for ch in value):
        return None
    return value


def string_field(buf: bytes | bytearray, table: int | None, voffset: int) -> str | None:
    return string_at(buf, ptr_field(buf, table, voffset))


def vector_tables(buf: bytes | bytearray, ptr: int | None) -> list[int]:
    if ptr is None:
        return []
    count = u32(buf, ptr)
    tables = []
    for index in range(count):
        element = ptr + 4 + index * 4
        tables.append(element + u32(buf, element))
    return tables


def widget_options_table(buf: bytes | bytearray, data_table: int | None) -> int | None:
    if data_table is None:
        return None
    if string_field(buf, data_table, 4) is not None:
        return data_table
    widget_options = ptr_field(buf, data_table, 4)
    if string_field(buf, widget_options, 4) is not None:
        return widget_options
    return None


def patch_node(buf: bytearray, node_table: int, target_names: set[str]) -> list[str]:
    changed: list[str] = []
    options = ptr_field(buf, node_table, 8)
    data_table = ptr_field(buf, options, 4) if options is not None else None
    widget_options = widget_options_table(buf, data_table)

    name = string_field(buf, widget_options, 4)
    touch_field = table_field(buf, widget_options, 34)
    if name in target_names and touch_field is not None:
        if buf[touch_field] != 0:
            buf[touch_field] = 0
        changed.append(name)

    for child in vector_tables(buf, ptr_field(buf, node_table, 6)):
        changed.extend(patch_node(buf, child, target_names))

    return changed


def patch_file(path: Path, target_names: set[str]) -> list[str]:
    buf = bytearray(path.read_bytes())
    root = u32(buf, 0)
    node_tree = ptr_field(buf, root, 10)
    if node_tree is None:
        raise RuntimeError(f"{path}: CSB root node tree not found")

    changed = patch_node(buf, node_tree, target_names)
    missing = sorted(target_names - set(changed))
    if missing:
        raise RuntimeError(f"{path}: target touch nodes not patched: {', '.join(missing)}")

    path.write_bytes(buf)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("app_dir", type=Path, help="Path to the extracted .app bundle")
    args = parser.parse_args()

    total = 0
    for relative_path, target_names in PATCHES.items():
        path = args.app_dir / relative_path
        if not path.is_file():
            raise FileNotFoundError(path)
        changed = patch_file(path, target_names)
        total += len(changed)
        print(f"{relative_path}: disabled touch on {', '.join(changed)}")

    print(f"Patched {total} non-interactive popup touch targets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
