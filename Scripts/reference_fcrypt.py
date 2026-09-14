#!/usr/bin/env python3
#
#  reference_fcrypt.py
#  FileCrypt
#
#  Copyright (c) 2026 Irshad
#  SPDX-License-Identifier: MIT
#
"""Independent reference implementation of the FileCrypt container format.

This file exists to *verify* the Swift implementation, not to be shipped. It is
written directly from the format description in `docs/FORMAT.md`, using only
Python's standard library plus `cryptography` (AES-GCM) and the system Argon2
library, and it shares no code with the app. If the Swift code and this script
agree in both directions, the on-disk format is what the specification says it
is.

    python3 Scripts/reference_fcrypt.py encrypt <in> <out> <password> [options]
    python3 Scripts/reference_fcrypt.py decrypt <in> <out> <password>
    python3 Scripts/reference_fcrypt.py info    <in>

Options for `encrypt`:
    --format {2,1}     container format (default 2, Argon2id)
    --salt <hex>       fixed salt, for reproducible fixtures
    --memory <kib>     Argon2id memory cost        (format 2, default 65536)
    --time-cost <n>    Argon2id passes             (format 2, default 3)
    --parallelism <n>  Argon2id lanes              (format 2, default 1)
    --iterations <n>   PBKDF2 rounds               (format 1, default 600000)
    --chunk-size <n>   plaintext bytes per record  (default 1048576)

Argon2id is reached through `libargon2` with ctypes. On macOS:

    brew install argon2
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import os
import struct
import sys
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Format description
# --------------------------------------------------------------------------

SALT_SIZE = 32
TAG_SIZE = 16
NONCE_SIZE = 12
DEFAULT_CHUNK = 1 << 20
CIPHER_ID = 1

FORMATS = {
    1: {
        "magic": b"FCRYPTv1",
        "kdf": 1,                 # PBKDF2-HMAC-SHA512
        "header_size": 88,
        "prefix_size": 56,
        "salt_offset": 24,
    },
    2: {
        "magic": b"FCRYPTv2",
        "kdf": 2,                 # Argon2id
        "header_size": 96,
        "prefix_size": 64,
        "salt_offset": 32,
    },
}


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# --------------------------------------------------------------------------
# Argon2id via libargon2
# --------------------------------------------------------------------------

_ARGON2 = None


def _argon2_library():
    global _ARGON2
    if _ARGON2 is not None:
        return _ARGON2

    # `find_library` only knows the OS's own search paths, which do not include
    # Homebrew on Apple silicon. Try the usual install locations explicitly.
    candidates = [
        "/opt/homebrew/lib/libargon2.dylib",
        "/usr/local/lib/libargon2.dylib",
        "/usr/lib/libargon2.so.1",
        "/usr/lib/x86_64-linux-gnu/libargon2.so.1",
        "libargon2.dylib",
        "libargon2.so.1",
        "libargon2.so",
    ]
    found = ctypes.util.find_library("argon2")
    if found:
        candidates.insert(0, found)

    for name in candidates:
        try:
            library = ctypes.CDLL(name)
        except OSError:
            continue
        library.argon2id_hash_raw.restype = ctypes.c_int
        library.argon2id_hash_raw.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        _ARGON2 = library
        return library

    raise RuntimeError(
        "libargon2 was not found. Install it (on macOS: `brew install argon2`) "
        "to work with format 2 containers."
    )


def argon2id(password: bytes, salt: bytes, memory_kib: int, time_cost: int,
             parallelism: int, length: int) -> bytes:
    library = _argon2_library()
    password_buffer = ctypes.create_string_buffer(password, max(len(password), 1))
    salt_buffer = ctypes.create_string_buffer(salt, max(len(salt), 1))
    output = ctypes.create_string_buffer(length)

    status = library.argon2id_hash_raw(
        time_cost, memory_kib, parallelism,
        ctypes.cast(password_buffer, ctypes.c_void_p), len(password),
        ctypes.cast(salt_buffer, ctypes.c_void_p), len(salt),
        ctypes.cast(output, ctypes.c_void_p), length,
    )
    if status != 0:
        raise RuntimeError(f"argon2id_hash_raw failed with status {status}")
    return output.raw[:length]


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------

def normalise(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_keys(password: str, salt: bytes, spec: dict):
    secret = normalise(password)
    version = spec["version"]

    if spec["kdf"] == 1:
        seed = hashlib.pbkdf2_hmac("sha512", secret, salt, spec["iterations"], 32)
    elif spec["kdf"] == 2:
        seed = argon2id(secret, salt, spec["memory"], spec["time_cost"],
                        spec["parallelism"], 32)
    else:
        raise ValueError(f"unknown kdf id {spec['kdf']}")

    label = f"FCRYPTv{version}"
    return (
        hkdf_sha256(seed, salt, f"{label}/aes-256-gcm".encode(), 32),
        hkdf_sha256(seed, salt, f"{label}/key-commitment".encode(), 32),
    )


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------

def build_prefix(spec: dict, chunk_size: int, salt: bytes) -> bytes:
    prefix = bytearray()
    prefix += spec["magic"]
    prefix += bytes([spec["version"]])          # format version
    prefix += bytes([spec["kdf"]])
    prefix += bytes([CIPHER_ID])
    prefix += bytes([0])                        # flags
    prefix += struct.pack("<I", chunk_size)

    if spec["kdf"] == 1:
        prefix += struct.pack("<I", spec["iterations"])
    else:
        prefix += struct.pack("<I", spec["memory"])
        prefix += struct.pack("<I", spec["time_cost"])
        prefix += struct.pack("<I", spec["parallelism"])

    prefix += struct.pack("<I", spec["header_size"])
    prefix += salt
    assert len(prefix) == spec["prefix_size"], (len(prefix), spec["prefix_size"])
    return bytes(prefix)


def parse_header(blob: bytes) -> dict:
    if len(blob) < 8:
        raise ValueError("file is smaller than a magic")

    magic = blob[:8]
    version = None
    for candidate, candidate_spec in FORMATS.items():
        if magic == candidate_spec["magic"]:
            version = candidate
            break
    if version is None:
        raise ValueError("bad magic: not a FileCrypt container")

    spec = dict(FORMATS[version])
    spec["version"] = version

    if len(blob) < spec["header_size"]:
        raise ValueError("file is smaller than its header")
    if blob[8] != version:
        raise ValueError(f"version byte {blob[8]} does not match the magic")
    if blob[9] != spec["kdf"]:
        raise ValueError(f"kdf id {blob[9]} does not match format {version}")
    if blob[10] != CIPHER_ID:
        raise ValueError(f"unsupported cipher {blob[10]}")
    if blob[11] != 0:
        raise ValueError("unknown flags")

    (chunk_size,) = struct.unpack("<I", blob[12:16])
    if spec["kdf"] == 1:
        spec["iterations"] = struct.unpack("<I", blob[16:20])[0]
        (header_size,) = struct.unpack("<I", blob[20:24])
    else:
        spec["memory"] = struct.unpack("<I", blob[16:20])[0]
        spec["time_cost"] = struct.unpack("<I", blob[20:24])[0]
        spec["parallelism"] = struct.unpack("<I", blob[24:28])[0]
        (header_size,) = struct.unpack("<I", blob[28:32])

    if header_size != spec["header_size"]:
        raise ValueError(f"header size {header_size} != {spec['header_size']}")

    spec["chunk_size"] = chunk_size
    spec["salt"] = blob[spec["salt_offset"]:spec["salt_offset"] + SALT_SIZE]
    spec["prefix"] = blob[: spec["prefix_size"]]
    spec["commitment"] = blob[spec["prefix_size"]: spec["header_size"]]
    return spec


def aad_for(header: bytes, index: int, is_final: bool, cipher_length: int) -> bytes:
    return (
        header
        + index.to_bytes(8, "big")
        + (b"\x01" if is_final else b"\x00")
        + struct.pack("<I", cipher_length)
    )


def nonce_for(index: int) -> bytes:
    nonce = b"\x00" * 4 + index.to_bytes(8, "big")
    assert len(nonce) == NONCE_SIZE
    return nonce


# --------------------------------------------------------------------------
# Container operations
# --------------------------------------------------------------------------

def encrypt_file(src: str, dst: str, password: str, *, version: int = 2,
                 chunk_size: int = DEFAULT_CHUNK, salt: bytes | None = None,
                 memory: int = 65_536, time_cost: int = 3, parallelism: int = 1,
                 iterations: int = 600_000) -> bytes:
    spec = dict(FORMATS[version])
    spec["version"] = version
    spec.update(memory=memory, time_cost=time_cost, parallelism=parallelism,
                iterations=iterations)

    salt = salt if salt is not None else os.urandom(SALT_SIZE)
    assert len(salt) == SALT_SIZE

    enc_key, commit_key = derive_keys(password, salt, spec)
    prefix = build_prefix(spec, chunk_size, salt)
    commitment = hmac.new(commit_key, prefix, hashlib.sha256).digest()
    header = prefix + commitment
    assert len(header) == spec["header_size"]

    aes = AESGCM(enc_key)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header)
        index = 0
        while True:
            chunk = fin.read(chunk_size)
            nxt = fin.read(1)
            is_final = nxt == b""
            if nxt:
                fin.seek(-1, os.SEEK_CUR)
            cipher_length = len(chunk) + TAG_SIZE
            aad = aad_for(header, index, is_final, cipher_length)
            sealed = aes.encrypt(nonce_for(index), chunk, aad)
            fout.write(struct.pack("<I", cipher_length))
            fout.write(sealed)
            if is_final:
                break
            index += 1
    return header


def decrypt_file(src: str, dst: str, password: str) -> None:
    with open(src, "rb") as fin:
        blob = fin.read()

    spec = parse_header(blob)
    enc_key, commit_key = derive_keys(password, spec["salt"], spec)

    if not hmac.compare_digest(
        hmac.new(commit_key, spec["prefix"], hashlib.sha256).digest(),
        spec["commitment"],
    ):
        raise ValueError("wrong password (key commitment mismatch)")

    aes = AESGCM(enc_key)
    header = blob[: spec["header_size"]]
    offset = spec["header_size"]
    index = 0
    out = bytearray()

    while offset < len(blob):
        (cipher_length,) = struct.unpack("<I", blob[offset:offset + 4])
        offset += 4
        sealed = blob[offset:offset + cipher_length]
        offset += cipher_length

        if len(sealed) != cipher_length:
            raise ValueError("truncated record")

        is_final = offset >= len(blob)
        aad = aad_for(header, index, is_final, cipher_length)
        try:
            out += aes.decrypt(nonce_for(index), sealed, aad)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"record {index} failed authentication") from exc
        if is_final:
            break
        index += 1

    with open(dst, "wb") as fout:
        fout.write(out)


def describe(path: str) -> str:
    with open(path, "rb") as handle:
        spec = parse_header(handle.read())

    lines = [
        f"format:      {spec['version']}",
        f"chunk size:  {spec['chunk_size']}",
    ]
    if spec["kdf"] == 1:
        lines.append(f"pbkdf2:      {spec['iterations']} rounds")
    else:
        lines.append(
            f"argon2id:    m={spec['memory']} KiB t={spec['time_cost']} p={spec['parallelism']}"
        )
    lines.append(f"salt:        {spec['salt'].hex()}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2

    command = argv[1]
    options: dict = {}
    positional: list[str] = []
    index = 2
    while index < len(argv):
        token = argv[index]
        if token == "--salt":
            options["salt"] = bytes.fromhex(argv[index + 1]); index += 2
        elif token == "--format":
            options["version"] = int(argv[index + 1]); index += 2
        elif token == "--memory":
            options["memory"] = int(argv[index + 1]); index += 2
        elif token == "--time-cost":
            options["time_cost"] = int(argv[index + 1]); index += 2
        elif token == "--parallelism":
            options["parallelism"] = int(argv[index + 1]); index += 2
        elif token == "--iterations":
            options["iterations"] = int(argv[index + 1]); index += 2
        elif token == "--chunk-size":
            options["chunk_size"] = int(argv[index + 1]); index += 2
        else:
            positional.append(token); index += 1

    if command == "info":
        print(describe(positional[0]))
        return 0

    if command in ("encrypt", "decrypt"):
        if len(positional) != 3:
            print(__doc__)
            return 2
        source, destination, password = positional
        if command == "encrypt":
            encrypt_file(source, destination, password, **options)
        else:
            decrypt_file(source, destination, password)
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
