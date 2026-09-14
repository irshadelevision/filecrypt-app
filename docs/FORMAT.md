# FileCrypt container format

Two formats exist. **Format 2 (Argon2id)** is what the app writes. **Format 1
(PBKDF2)** is legacy: it is read, never written, and exists so containers made by
earlier builds still open.

A reader picks the layout from the first eight bytes, so an unsupported
container is rejected on its magic rather than half-parsed.

| | Format 1 | Format 2 |
|---|---|---|
| magic | `FCRYPTv1` | `FCRYPTv2` |
| header size | 88 bytes | 96 bytes |
| key commitment covers | bytes `0..<56` | bytes `0..<64` |
| key derivation | PBKDF2-HMAC-SHA512 | **Argon2id** |
| status | read-only | current |

All integers are **little-endian** unless stated otherwise. The format is
explicit about byte order so it does not depend on host endianness, alignment,
or on how a language represents a byte buffer.

```
┌──────────────────────── header (88 or 96 bytes) ───────────────────────┐
│ magic │ ver │ kdf │ cipher │ flags │ chunk │ kdf params │ size │ salt │ commit │
└────────────────────────────────────────────────────────────────────────┘
┌─ record 0 ─┐┌─ record 1 ─┐                          ┌─ record N-1 ─┐
│ len │ ct ‖ tag │ len │ ct ‖ tag │ ...                │ len │ ct ‖ tag │
└─────┘         └─────┘                               └─────┘
```

## Format 2 header (current)

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | ASCII `FCRYPTv2` |
| 8 | 1 | format version | `2` |
| 9 | 1 | KDF identifier | `2` = Argon2id |
| 10 | 1 | cipher identifier | `1` = AES-256-GCM (96-bit nonce, 128-bit tag) |
| 11 | 1 | flags | bit 0 = payload is a folder archive; unknown bits are a hard error |
| 12 | 4 | chunk size | plaintext bytes per record |
| 16 | 4 | memory | Argon2id memory cost, KiB |
| 20 | 4 | time cost | Argon2id passes |
| 24 | 4 | parallelism | Argon2id lanes |
| 28 | 4 | header size | `96` |
| 32 | 32 | salt | CSPRNG output |
| 64 | 32 | key commitment | HMAC-SHA256 over bytes `0..<64` |

## Format 1 header (legacy, read-only)

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | ASCII `FCRYPTv1` |
| 8 | 1 | format version | `1` |
| 9 | 1 | KDF identifier | `1` = PBKDF2-HMAC-SHA512 |
| 10 | 1 | cipher identifier | `1` = AES-256-GCM |
| 11 | 1 | flags | `0` in practice; bit 0 is defined but unused by format 1 |
| 12 | 4 | chunk size | plaintext bytes per record |
| 16 | 4 | PBKDF2 iterations | work factor |
| 20 | 4 | header size | `88` |
| 24 | 32 | salt | CSPRNG output |
| 56 | 32 | key commitment | HMAC-SHA256 over bytes `0..<56` |

## Bounds

A reader **must** reject a container whose magic, version byte, KDF identifier,
cipher identifier, flags or header size do not match exactly, or whose
parameters fall outside these ranges. They exist so a hostile container cannot
make a reader allocate unreasonable memory or burn unbounded CPU *before*
authentication fails.

| Field | Minimum | Maximum |
|-------|--------:|--------:|
| chunk size | 1 024 | 16 777 216 |
| Argon2id memory | 8 KiB | 2 097 152 KiB (2 GiB) |
| Argon2id time cost | 1 | 64 |
| Argon2id parallelism | 1 | 16 |
| PBKDF2 iterations (format 1) | 1 000 | 20 000 000 |

Argon2 additionally requires `memory >= 8 * parallelism`; a reader must reject
a header that violates it rather than pass it to the library.

## Key schedule

### Format 2

```
passwordBytes = NFC(password).utf8
seed          = Argon2id(passwordBytes, salt, memory, timeCost, parallelism, 32)
aesKey        = HKDF-SHA256(seed, salt, "FCRYPTv2/aes-256-gcm",    32)
commitKey     = HKDF-SHA256(seed, salt, "FCRYPTv2/key-commitment", 32)
```

`Argon2id` is the Argon2id variant (not `d`, not `i`) with Argon2 version
`0x13`, no secret key and no associated data.

### Format 1

```
passwordBytes = NFC(password).utf8
seed          = PBKDF2-HMAC-SHA512(passwordBytes, salt, iterations, 32)
aesKey        = HKDF-SHA256(seed, salt, "FCRYPTv1/aes-256-gcm",    32)
commitKey     = HKDF-SHA256(seed, salt, "FCRYPTv1/key-commitment", 32)
```

The `info` label is tied to the format version. Format 1 files must keep using
the `v1` labels or they will not open.

`HKDF-SHA256` here is the standard RFC 5869 extract-then-expand with the given
`salt` and `info`, producing 32 bytes. It runs *after* the expensive KDF purely
to give the two subkeys domain separation: a single 32-byte KDF output must not
be used both to protect the file and to authenticate a public header value.

### Key commitment

```
commitment = HMAC-SHA256(commitKey, header[0 ..< prefixSize])
```

The commitment is computed over the header prefix, which does **not** include
the commitment field itself (`prefixSize` is 64 for format 2, 56 for format 1).
A reader recomputes it and compares in constant time; a mismatch means the
password is wrong (or the header was altered), and the reader must stop before
touching any record.

## Flags

| Bit | Meaning |
|----:|---------|
| 0 | The plaintext is a `tar` archive of a folder rather than a single file's bytes |
| 1-7 | Reserved. A reader must reject a container that sets any of them. |

A reader that does not understand bit 0 must reject the container rather than
treat the payload as a file, which is what the reserved byte exists for.

## Folder archives

When bit 0 is set the plaintext is a **POSIX `ustar` archive**, extended with
**PAX** records where `ustar` cannot express a value (a path longer than 100
bytes, a link target longer than 100 bytes, a file larger than 8 GiB).

An extractor must treat the archive as untrusted input:

* reject absolute paths and any path containing a `..` or `.` component,
* reject an entry whose path lies beneath a symlink created by an earlier
  entry, since writing through such a link escapes the destination,
* refuse to write outside the destination directory after path standardisation.

Symlinks are stored as symlinks and never followed, both to preserve them and
because following one turns a link loop into a non-terminating walk.

The archive's single top-level directory entry names the original folder. A
caller that names the destination explicitly should unwrap it, so restoring
`Project.fcrypt` to `Restored` yields `Restored/README.md` rather than
`Restored/Project/README.md`.

## Records

Identical in both formats:

```
uint32le ciphertextLength ‖ ciphertext ‖ tag
```

* `ciphertextLength` counts the ciphertext **and** the 16-byte GCM tag, so it is
  at least 16 and at most `chunkSize + 16`.
* `ciphertext` is `plaintextLength = ciphertextLength - 16` bytes.
* `tag` is the 16-byte AES-GCM authentication tag.

The final record **must** be the one that ends exactly at end of file. A file
whose header is not followed by at least one record is invalid.

### Per-record nonce

```
nonce = 0x00000000 ‖ uint64be(recordIndex)      # 12 bytes total
```

Nonce reuse would be catastrophic for GCM. It cannot happen here: the AES key is
derived from a fresh 32-byte CSPRNG salt for every encryption, so a given key
only ever seals the records of one file, each with a distinct index.

### Per-record additional authenticated data

```
aad = header[0 ..< headerSize] ‖ uint64be(recordIndex) ‖ isFinal ‖ uint32le(ciphertextLength)
```

where `isFinal` is a single byte, `1` for the last record of the file and `0`
otherwise, and `ciphertextLength` is the value from the record's own length
prefix. The header used is the full encoded header including the commitment.

This binds together:

* the header — so the salt, KDF parameters, chunk size and flags are
  authenticated by every record, not merely parsed,
* the record's position — so records cannot be reordered or replayed,
* whether the record is last — so the file cannot be truncated or extended,
* the record's own framing — so the length prefix cannot be edited.

## Encrypting

```
1.  salt ← 32 CSPRNG bytes
2.  derive seed, aesKey, commitKey
3.  write header (with commitment)
4.  index ← 0; read up to chunkSize bytes into `current`
5.  if the input was empty:
        seal one record: plaintext = b"", index = 0, isFinal = 1
    else:
        loop:
            next ← read up to chunkSize bytes
            isFinal ← next is empty
            seal `current` as record `index` with isFinal
            if isFinal: stop
            current ← next; index ← index + 1
```

A zero-byte input still produces one authenticated record holding no plaintext,
so an empty file round trips instead of being indistinguishable from a
truncation.

## Decrypting

```
1.  read the 8-byte magic, pick the layout, read the rest of the header
2.  validate every header field against the bounds above
3.  derive the keys; verify the commitment — stop here if it fails
4.  consumed ← headerSize; index ← 0
5.  while consumed < fileSize:
        read uint32le ciphertextLength
        validate 16 ≤ ciphertextLength ≤ chunkSize + 16
        validate consumed + 4 + ciphertextLength ≤ fileSize
        read that many bytes
        isFinal ← (consumed == fileSize)
        verify and open the record with the nonce and AAD above
        write the plaintext
        if isFinal: done
        index ← index + 1
6.  if no record was the final one, the file is truncated
```

A reader must not emit plaintext to its final destination until the whole file
has authenticated. FileCrypt writes to a temporary file and renames it into
place, which satisfies this.

## Overhead

* 88 bytes of header (format 1) or 96 bytes (format 2).
* 4 bytes of framing per record.
* 16 bytes of tag per record.

With the default 1 MiB chunk size that is under 100 bytes plus 0.002 % — a 1 GiB
file grows by about 16.5 KiB.

## Known-answer vectors

`Tests/FileCryptCoreTests/Argon2Tests.swift` pins Argon2id against values
produced by the reference command-line tool:

```
printf 'password' | argon2 somesalt -id -t 2 -m 16 -p 1 -l 32 -r
  -> 09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7

printf 'password' | argon2 somesalt -id -t 3 -m 12 -p 4 -l 32 -r
  -> a6813fd21d9c8dbbfe5253c381154e1eac25982018a392c5e6578caef42a56b2
```

(`-m N` means `2^N` KiB, so `-m 16` is 64 MiB.)

`Tests/FileCryptCoreTests/KeyDerivationTests.swift` pins PBKDF2-HMAC-SHA512
(1, 2 and 4096 rounds on `"password"` / `"salt"`) and HKDF-SHA256 against
RFC 5869 test case 1.

`Tests/FileCryptCoreTests/InteropTests.swift` embeds one complete container per
format, both built by `Scripts/reference_fcrypt.py`:

| | Format 2 | Format 1 |
|---|---|---|
| password | `interop-fixture-password` | `interop-fixture-password` |
| salt | `000102…1f` (32 bytes) | `000102…1f` (32 bytes) |
| parameters | Argon2id m=1024 KiB, t=2, p=1 | PBKDF2 1000 rounds |
| chunk size | 1024 | 1024 |
| plaintext | `(i * 37 + 11) mod 256`, `i` in `0..<2500` | same |
| container size | 2656 bytes | 2648 bytes |

A conforming implementation must decrypt both, and must reproduce the format 2
container byte for byte when encrypting the same input with the same salt and
parameters.
