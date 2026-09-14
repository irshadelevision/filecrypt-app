#!/usr/bin/env python3
#
#  counter_pattern.py
#  FileCrypt
#
#  Copyright (c) 2026 Irshad
#  SPDX-License-Identifier: MIT
#
"""Generate and verify a large file whose every 8 bytes encode their own offset.

The file is a stream of little-endian `UInt64` values `0, 1, 2, 3, …`, so the
data at byte offset *n* depends on *n* alone. That makes it maximally sensitive
to the two failure modes a large-file test is looking for:

* a skipped or duplicated region,
* a region written at the wrong offset (any shift by 8 bytes is visible).

It also means the file never has to exist as a whole: `compare` regenerates the
expected bytes on the fly, so verifying a 100 GB round trip needs no extra disk
beyond the file being checked.

    counter_pattern.py write   <path> <total-bytes> [block-bytes]
    counter_pattern.py compare <path> <total-bytes> [block-bytes]
"""

from __future__ import annotations

import os
import sys
from array import array

DEFAULT_BLOCK = 8 << 20   # 8 MiB per write


def block_bytes_for(index: int, count: int) -> bytes:
    """`count` little-endian UInt64 values starting at `index`."""
    return array("Q", range(index, index + count)).tobytes()


def write(path: str, total: int, block: int) -> None:
    per_block = block // 8
    written = 0
    index = 0
    with open(path, "wb", buffering=0) as handle:
        while written < total:
            remaining = total - written
            count = per_block if remaining >= block else remaining // 8
            if count == 0:
                # A tail shorter than 8 bytes; pad deterministically.
                handle.write(bytes(remaining))
                written += remaining
                break
            payload = block_bytes_for(index, count)
            handle.write(payload)
            written += len(payload)
            index += count
    if written != total:
        raise SystemExit(f"wrote {written} bytes, expected {total}")


def compare(path: str, total: int, block: int) -> int:
    per_block = block // 8
    checked = 0
    index = 0
    with open(path, "rb", buffering=0) as handle:
        while checked < total:
            remaining = total - checked
            count = per_block if remaining >= block else remaining // 8
            if count == 0:
                tail = handle.read(remaining)
                if tail != bytes(remaining):
                    print(f"MISMATCH in the final {remaining} bytes at offset {checked}")
                    return 1
                checked += remaining
                break
            chunk = handle.read(count * 8)
            if len(chunk) != count * 8:
                print(f"SHORT READ: expected {count * 8} bytes at offset {checked}, got {len(chunk)}")
                return 1
            if chunk != block_bytes_for(index, count):
                # Narrow it down so the report is useful.
                expected = block_bytes_for(index, count)
                for offset in range(0, len(chunk), 8):
                    if chunk[offset:offset + 8] != expected[offset:offset + 8]:
                        print(f"MISMATCH at byte offset {checked + offset}")
                        print(f"  expected {expected[offset:offset+8].hex()}")
                        print(f"  actual   {chunk[offset:offset+8].hex()}")
                        return 1
                print(f"MISMATCH within the block at offset {checked}")
                return 1
            checked += len(chunk)
            index += count
    return 0


def parse_size(text: str) -> int:
    text = text.strip().upper()
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40, "B": 1}
    for suffix, multiplier in units.items():
        if text.endswith(suffix):
            return int(float(text[:-1]) * multiplier)
    return int(text)


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2

    mode, path, total_text = argv[1], argv[2], argv[3]
    total = parse_size(total_text)
    block = parse_size(argv[4]) if len(argv) > 4 else DEFAULT_BLOCK

    if mode == "write":
        write(path, total, block)
        return 0
    if mode == "compare":
        return compare(path, total, block)

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
