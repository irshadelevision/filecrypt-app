#!/bin/bash
#
#  smoke.sh
#  FileCrypt
#
#  Copyright (c) 2026 Irshad
#  SPDX-License-Identifier: MIT
#
#
# End-to-end smoke test for everything that lives outside the unit-test target:
# the CLI surface, its error paths, and interoperability against the
# independent Python implementation of the container format.
#
#   ./Scripts/smoke.sh [path-to-fcrypt]
#
# Defaults to build/fcrypt, falling back to the debug build. Run ./build.sh
# first if neither exists.
#
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

BIN="${1:-}"
if [ -z "$BIN" ]; then
	for candidate in build/fcrypt .build/release/fcrypt .build/debug/fcrypt; do
		if [ -x "$candidate" ]; then BIN="$candidate"; break; fi
	done
fi

if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
	echo "fcrypt binary not found; run ./build.sh first" >&2
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
WORK_DIR="$WORK"

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

check() { # check <description> <command...>
	local description="$1"; shift
	if "$@" >/dev/null 2>&1; then ok "$description"; else bad "$description"; fi
}

refuses() { # refuses <description> <command...> -- must exit non-zero
	local description="$1"; shift
	if "$@" >/dev/null 2>&1; then bad "$description (it succeeded)"; else ok "$description"; fi
}

random_file() { # random_file <path> <bytes>
	if [ "$2" -eq 0 ]; then
		: > "$1"
	else
		dd if=/dev/urandom of="$1" bs=65536 count=$(( ($2 + 65535) / 65536 )) 2>/dev/null
		truncate -s "$2" "$1"
	fi
}

echo "Using $BIN"
echo

# ---------------------------------------------------------------------------
echo "Round trips (real work factor)"
# ---------------------------------------------------------------------------
for size in 0 1 1023 4096 4097 250000 1200000; do
	random_file "$WORK/p$size" "$size"
	if "$BIN" encrypt --quiet --password 'smoke test passphrase' "$WORK/p$size" "$WORK/c$size" 2>/dev/null &&
	   "$BIN" decrypt --quiet --password 'smoke test passphrase' "$WORK/c$size" "$WORK/r$size" 2>/dev/null &&
	   cmp -s "$WORK/p$size" "$WORK/r$size"; then
		ok "$size bytes round trip"
	else
		bad "$size bytes round trip"
	fi
done

# ---------------------------------------------------------------------------
echo
echo "Non-interactive password sources"
# ---------------------------------------------------------------------------
random_file "$WORK/src" 5000
FILEPW='smoke-env-secret' "$BIN" encrypt --quiet --password-env FILEPW "$WORK/src" "$WORK/env.fcrypt" 2>/dev/null &&
	FILEPW='smoke-env-secret' "$BIN" decrypt --quiet --password-env FILEPW "$WORK/env.fcrypt" "$WORK/env.out" 2>/dev/null &&
	cmp -s "$WORK/src" "$WORK/env.out" && ok "--password-env" || bad "--password-env"

printf 'smoke-stdin-secret\n' | "$BIN" encrypt --quiet --password-stdin "$WORK/src" "$WORK/stdin.fcrypt" 2>/dev/null &&
	printf 'smoke-stdin-secret\n' | "$BIN" decrypt --quiet --password-stdin "$WORK/stdin.fcrypt" "$WORK/stdin.out" 2>/dev/null &&
	cmp -s "$WORK/src" "$WORK/stdin.out" && ok "--password-stdin (switch before positionals)" || bad "--password-stdin"

printf 'smoke-file-secret\n' > "$WORK/pwfile"
chmod 600 "$WORK/pwfile"
"$BIN" encrypt --quiet --password-file "$WORK/pwfile" "$WORK/src" "$WORK/file.fcrypt" 2>/dev/null &&
	"$BIN" decrypt --quiet --password-file "$WORK/pwfile" "$WORK/file.fcrypt" "$WORK/file.out" 2>/dev/null &&
	cmp -s "$WORK/src" "$WORK/file.out" && ok "--password-file" || bad "--password-file"

"$BIN" encrypt --quiet --password=inline-secret "$WORK/src" "$WORK/inline.fcrypt" 2>/dev/null &&
	"$BIN" decrypt --quiet --password=inline-secret "$WORK/inline.fcrypt" "$WORK/inline.out" 2>/dev/null &&
	cmp -s "$WORK/src" "$WORK/inline.out" && ok "--password=value form" || bad "--password=value form"

# ---------------------------------------------------------------------------
echo
echo "Error paths"
# ---------------------------------------------------------------------------
random_file "$WORK/plain" 500
"$BIN" encrypt --quiet --password pw "$WORK/plain" "$WORK/ok.fcrypt" 2>/dev/null

refuses "wrong password is refused" "$BIN" decrypt --quiet --password nope "$WORK/ok.fcrypt" "$WORK/wrong.out"
check   "no output left by the failed run" test ! -e "$WORK/wrong.out"
refuses "input == output is refused" "$BIN" encrypt --password pw "$WORK/plain" "$WORK/plain"
refuses "missing input is refused" "$BIN" encrypt --password pw "$WORK/absent" "$WORK/o"
refuses "empty password is refused" "$BIN" encrypt --password '' "$WORK/plain" "$WORK/e.fcrypt"
refuses "absurd Argon2 memory is refused" "$BIN" encrypt --password pw --memory 999999999 "$WORK/plain" "$WORK/i.fcrypt"
refuses "absurd Argon2 time cost is refused" "$BIN" encrypt --password pw --time-cost 9999 "$WORK/plain" "$WORK/t.fcrypt"
refuses "zero Argon2 lanes are refused" "$BIN" encrypt --password pw --parallelism 0 "$WORK/plain" "$WORK/p.fcrypt"
refuses "unparseable --memory is refused" "$BIN" encrypt --password pw --memory abc "$WORK/plain" "$WORK/m1.fcrypt"
refuses "out-of-range --memory is refused" "$BIN" encrypt --password pw --memory 999999999999 "$WORK/plain" "$WORK/m2.fcrypt"
refuses "negative --memory is refused" "$BIN" encrypt --password pw --memory -5 "$WORK/plain" "$WORK/m3.fcrypt"
refuses "unparseable --time-cost is refused" "$BIN" encrypt --password pw --time-cost 2x "$WORK/plain" "$WORK/m4.fcrypt"
check   "no file is produced for a bad option" test ! -e "$WORK/m1.fcrypt"
refuses "absurd chunk size is refused" "$BIN" encrypt --password pw --chunk-size 16 "$WORK/plain" "$WORK/k.fcrypt"
refuses "missing value for --password is reported" "$BIN" encrypt --password
refuses "info on a non-container is refused" "$BIN" info "$WORK/plain"
refuses "unknown command is refused" "$BIN" frobnicate a b
refuses "too few arguments is refused" "$BIN" encrypt only-one.fcrypt

# ---------------------------------------------------------------------------
echo
echo "Tamper detection"
# ---------------------------------------------------------------------------
random_file "$WORK/tamper" 200000
"$BIN" encrypt --quiet --password pw "$WORK/tamper" "$WORK/tamper.fcrypt" 2>/dev/null

tamper() { # tamper <mode> <source> <destination>
	python3 - "$1" "$2" "$3" <<'PY'
import shutil, sys
mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
b = bytearray(open(src, "rb").read())
if mode == "truncate-byte":    b = b[:-1]
elif mode == "truncate-half":  b = b[: len(b) // 2]
elif mode == "truncate-record": b = b[: 88 + 4 + 65536]
elif mode == "flip-magic":     b[0] ^= 1
elif mode == "flip-salt":      b[30] ^= 1
elif mode == "flip-header-end":b[87] ^= 1
elif mode == "flip-ciphertext":b[200] ^= 1
elif mode == "flip-tag":       b[-1] ^= 1
elif mode == "append":         b += b"\x00" * 64
elif mode == "header-only":    b = b[:88]
open(dst, "wb").write(bytes(b))
PY
}

for mode in truncate-byte truncate-half truncate-record flip-magic flip-salt \
            flip-header-end flip-ciphertext flip-tag append header-only; do
	tamper "$mode" "$WORK/tamper.fcrypt" "$WORK/bad.fcrypt"
	refuses "$mode is refused" "$BIN" decrypt --quiet --password pw "$WORK/bad.fcrypt" "$WORK/bad.out"
	check   "$mode leaves no partial output" test ! -e "$WORK/bad.out"
done

# ---------------------------------------------------------------------------
echo
echo "Interoperability with Scripts/reference_fcrypt.py"
# ---------------------------------------------------------------------------
FAST_ARGS=(--chunk-size 4096 --memory 1024 --time-cost 1 --parallelism 1)

if python3 -c "import cryptography; import ctypes; ctypes.CDLL('/opt/homebrew/lib/libargon2.dylib')" >/dev/null 2>&1 ||
   python3 -c "import cryptography; import ctypes.util, ctypes; ctypes.CDLL(ctypes.util.find_library('argon2'))" >/dev/null 2>&1 ||
   python3 -c "import cryptography; from argon2.low_level import Type" >/dev/null 2>&1; then

	for size in 0 1 4096 4097 100000; do
		random_file "$WORK/x$size" "$size"

		"$BIN" encrypt --quiet "${FAST_ARGS[@]}" --password 'interop 🔐' "$WORK/x$size" "$WORK/x$size.fcrypt" 2>/dev/null &&
			python3 Scripts/reference_fcrypt.py decrypt "$WORK/x$size.fcrypt" "$WORK/py$size" 'interop 🔐' 2>/dev/null &&
			cmp -s "$WORK/x$size" "$WORK/py$size" &&
			ok "swift -> python (Argon2id), $size bytes" || bad "swift -> python (Argon2id), $size bytes"

		python3 Scripts/reference_fcrypt.py encrypt "$WORK/x$size" "$WORK/pyc$size" 'interop 🔐' "${FAST_ARGS[@]}" 2>/dev/null &&
			"$BIN" decrypt --quiet --password 'interop 🔐' "$WORK/pyc$size" "$WORK/sw$size" 2>/dev/null &&
			cmp -s "$WORK/x$size" "$WORK/sw$size" &&
			ok "python -> swift (Argon2id), $size bytes" || bad "python -> swift (Argon2id), $size bytes"
	done

	# Legacy format 1 support must survive.
	random_file "$WORK/legacy" 50000
	python3 Scripts/reference_fcrypt.py encrypt "$WORK/legacy" "$WORK/legacy.fcrypt" 'legacy pw' \
		--format 1 --iterations 1000 --chunk-size 4096 2>/dev/null &&
		"$BIN" decrypt --quiet --password 'legacy pw' "$WORK/legacy.fcrypt" "$WORK/legacy.out" 2>/dev/null &&
		cmp -s "$WORK/legacy" "$WORK/legacy.out" &&
		ok "legacy format 1 container still opens" || bad "legacy format 1 container still opens"

	"$BIN" info "$WORK/legacy.fcrypt" 2>/dev/null | grep -q "PBKDF2" &&
		ok "legacy container is reported as PBKDF2" || bad "legacy container is reported as PBKDF2"
else
	echo "  skipped (python 'cryptography' or libargon2 is not available)"
fi

# ---------------------------------------------------------------------------
echo
echo "Password generator"
# ---------------------------------------------------------------------------
GENERATED=$("$BIN" generate --quiet 2>/dev/null)
[ ${#GENERATED} -eq 20 ] && ok "default length is 20" || bad "default length is 20 (got ${#GENERATED})"

for length in 8 16 40 128 256; do
	value=$("$BIN" generate --quiet --length "$length" 2>/dev/null)
	[ ${#value} -eq "$length" ] && ok "--length $length is respected" || bad "--length $length is respected"
done

count=$("$BIN" generate --quiet --length 16 --count 5 2>/dev/null | wc -l | tr -d ' ')
[ "$count" = "5" ] && ok "--count 5 prints 5 lines" || bad "--count 5 prints 5 lines (got $count)"

# The default pool excludes look-alike characters.
for _ in 1 2 3; do
	value=$("$BIN" generate --quiet --length 200 2>/dev/null)
	case "$value" in
		*[0Oo1lI]*) bad "look-alike characters are excluded" ;;
		*) ok "look-alike characters are excluded" ;;
	esac
done

value=$("$BIN" generate --quiet --length 200 --no-symbols 2>/dev/null)
case "$value" in
	*[!A-Za-z0-9]*) bad "--no-symbols yields letters and digits only" ;;
	*) ok "--no-symbols yields letters and digits only" ;;
esac

# Every generated password must actually work.
random_file "$WORK/genplain" 20000
GENPW=$("$BIN" generate --quiet --length 24 2>/dev/null)
"$BIN" encrypt --quiet --password "$GENPW" "$WORK/genplain" "$WORK/gen.fcrypt" 2>/dev/null &&
	"$BIN" decrypt --quiet --password "$GENPW" "$WORK/gen.fcrypt" "$WORK/gen.out" 2>/dev/null &&
	cmp -s "$WORK/genplain" "$WORK/gen.out" &&
	ok "a generated password round trips through the CLI" || bad "a generated password round trips"

# Different every time.
if [ "$("$BIN" generate --quiet 2>/dev/null)" != "$("$BIN" generate --quiet 2>/dev/null)" ]; then
	ok "successive passwords differ"
else
	bad "successive passwords differ"
fi

refuses "a too-short --length is refused" "$BIN" generate --length 3
refuses "an unparseable --length is refused" "$BIN" generate --length abc
refuses "an out-of-range --count is refused" "$BIN" generate --count 99999

# ---------------------------------------------------------------------------
echo
echo "Self test"
# ---------------------------------------------------------------------------
check "fcrypt selftest" "$BIN" selftest

# ---------------------------------------------------------------------------
echo
if [ "$FAIL" -eq 0 ]; then
	printf '\033[32m%s checks passed\033[0m\n' "$PASS"
	exit 0
fi
printf '\033[31m%s passed, %s failed\033[0m\n' "$PASS" "$FAIL"
exit 1
