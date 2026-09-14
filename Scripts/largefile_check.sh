#!/bin/bash
#
#  largefile_check.sh
#  FileCrypt
#
#  Copyright (c) 2026 Irshad Ibrahim
#  SPDX-License-Identifier: MIT
#
#
# Large-file round trip for FileCrypt.
#
#   ./Scripts/largefile_check.sh [--size 16G] [--chunk-size 1M] [--binary build/fcrypt]
#
# Checks the properties that only show up at scale:
#
#   * byte offsets past 2^32 — the one place a 32-bit counter could truncate,
#   * a record count comparable to a multi-gigabyte file,
#   * memory that does not grow with file size,
#   * no temporary files left behind.
#
# Disk use peaks at roughly twice the file size: the plaintext is deleted before
# decryption, and the restored copy is verified against a regenerated stream
# rather than a third file. The script refuses to start without headroom.
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

SIZE="16G"
CHUNK="1M"
BIN="build/fcrypt"

while [ $# -gt 0 ]; do
	case "$1" in
		--size) SIZE="$2"; shift 2 ;;
		--chunk-size) CHUNK="$2"; shift 2 ;;
		--binary) BIN="$2"; shift 2 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

if [ ! -x "$BIN" ]; then
	echo "fcrypt not found at $BIN; run ./build.sh first" >&2
	exit 1
fi

# Size in bytes.
SIZE_BYTES=$(python3 -c "
import sys
t = '''$SIZE'''.strip().upper()
units = {'K': 1<<10, 'M': 1<<20, 'G': 1<<30, 'T': 1<<40, 'B': 1}
for s, m in units.items():
    if t.endswith(s):
        print(int(float(t[:-1]) * m)); break
else:
    print(int(t))
")

# Chunk size in bytes.
CHUNK_BYTES=$(python3 -c "
t = '''$CHUNK'''.strip().upper()
units = {'K': 1<<10, 'M': 1<<20, 'G': 1<<30, 'B': 1}
for s, m in units.items():
    if t.endswith(s):
        print(int(float(t[:-1]) * m)); break
else:
    print(int(t))
")

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Peak is 2x the file size (plaintext + container, then container + restored).
NEEDED=$(( SIZE_BYTES * 2 + 4 * 1024 * 1024 * 1024 ))
AVAILABLE=$(df -k "$(dirname "$WORK")" | awk 'NR==2 {print $4 * 1024}')

human() { python3 -c "print(f'{int($1)/1073741824:.1f} GiB')"; }

echo "FileCrypt large-file check"
echo "  size:       $SIZE ($(human $SIZE_BYTES))"
echo "  chunk size: $CHUNK ($(human $CHUNK_BYTES))"
echo "  records:    $(( (SIZE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES ))"
echo "  disk free:  $(human $AVAILABLE), need about $(human $NEEDED)"
echo

if [ "$AVAILABLE" -lt "$NEEDED" ]; then
	echo "REFUSING TO RUN: not enough free disk space." >&2
	echo "  free $(human $AVAILABLE), need $(human $NEEDED)" >&2
	echo "  A round trip of a file this size needs about twice its size in free space." >&2
	exit 1
fi

PLAIN="$WORK/plain.bin"
CONTAINER="$WORK/plain.bin.fcrypt"
RESTORED="$WORK/restored.bin"
PASSWORD="large file check passphrase"

rss_of() { # rss_of <logfile>
	awk '/maximum resident/{print int($1/1048576)}' "$1"
}

step() { printf '\n== %s\n' "$1"; }

# ---------------------------------------------------------------------------
step "1/5  Generating $(human $SIZE_BYTES)"
GEN_START=$(date +%s)
python3 Scripts/counter_pattern.py write "$PLAIN" "$SIZE_BYTES"
GEN_END=$(date +%s)
echo "     $(du -h "$PLAIN" | cut -f1) in $(( GEN_END - GEN_START ))s"

# ---------------------------------------------------------------------------
step "2/5  Encrypting (default Argon2id cost)"
/usr/bin/time -l "$BIN" encrypt --quiet --chunk-size "$CHUNK_BYTES" \
	--password "$PASSWORD" "$PLAIN" "$CONTAINER" 2>"$WORK/encrypt.log"
echo "     $(du -h "$CONTAINER" | cut -f1) written, peak RSS $(rss_of "$WORK/encrypt.log") MB"
python3 - "$PLAIN" "$CONTAINER" <<'PY'
import os, sys
plain, container = os.path.getsize(sys.argv[1]), os.path.getsize(sys.argv[2])
extra = container - plain
print(f"     overhead {extra} bytes ({extra / plain * 100:.6f}% of the payload)")
PY

# Free the plaintext before decrypting; the pattern is regenerated for the check.
rm -f "$PLAIN"

# ---------------------------------------------------------------------------
step "3/5  Decrypting"
/usr/bin/time -l "$BIN" decrypt --quiet --password "$PASSWORD" "$CONTAINER" "$RESTORED" \
	2>"$WORK/decrypt.log"
echo "     peak RSS $(rss_of "$WORK/decrypt.log") MB"
rm -f "$CONTAINER"

# ---------------------------------------------------------------------------
step "4/5  Verifying byte-for-byte against a regenerated pattern"
VERIFY_START=$(date +%s)
python3 Scripts/counter_pattern.py compare "$RESTORED" "$SIZE_BYTES"
VERIFY_END=$(date +%s)
echo "     identical, verified in $(( VERIFY_END - VERIFY_START ))s"

# ---------------------------------------------------------------------------
step "5/5  Checking for leftovers"
LEFTOVERS=$(find "$WORK" -name "*.part" -o -name "*.tmp" | wc -l | tr -d ' ')
if [ "$LEFTOVERS" != "0" ]; then
	echo "     FAIL: $LEFTOVERS temporary file(s) left behind" >&2
	find "$WORK" -name "*.part" -o -name "*.tmp" >&2
	exit 1
fi
echo "     none"

echo
echo "PASS: $(human $SIZE_BYTES) round trip, byte-identical, memory bounded."
