# FileCrypt

A native macOS app that encrypts a single file with **AES-256-GCM**, keyed from a
password through a memory-hard **Argon2id → HKDF-SHA256** chain.

Pick a file, type or generate a password, get a `.fcrypt` container. Pick the
container, enter the same password, get the file back.

No account, no network, no keychain, no telemetry, no recovery. The password is
the only thing that can open the file, and it never leaves the Mac.

**Free and open source**, under the [MIT License](LICENSE).

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Using the app](#using-the-app)
- [The password generator](#the-password-generator)
- [Using the command line](#using-the-command-line)
- [How the encryption works](#how-the-encryption-works)
- [Container format](#container-format)
- [Safety properties](#safety-properties)
- [What this does not protect against](#what-this-does-not-protect-against)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Development notes](#development-notes)
- [Licence](#licence)
- [Attribution](#attribution)

---

## Requirements

- macOS 14 (Sonoma) or newer
- Swift 6 toolchain (Xcode 16+) to build — not needed to run the built app
- No package dependencies to resolve

Optional, only for the verification scripts:

- `cryptography` (Python) and `libargon2` (`brew install argon2`)

---

## Quick start

```bash
./build.sh release run
```

This produces two things:

| Path | What it is |
|------|------------|
| `build/FileCrypt.app` | the GUI app, ad-hoc signed and double-clickable |
| `build/fcrypt` | a command-line tool for scripting and automation |

You can also open the package in Xcode:

```bash
open Package.swift
```

The first build renders the app icon from `Scripts/make_icon.swift`; there are no
binary art assets in the repository.

---

## Using the app

The window is a three-step form.

### 1 · Choose a file

Drag a file onto the drop zone, or press **Choose File…**. The app reads the
first eight bytes and switches itself to **Encrypt** or **Decrypt** depending on
what it finds, so you rarely have to touch the mode switch.

- Dropping a **folder** is refused immediately, with an explanation, rather than
  letting you get as far as typing a password.
- The destination is shown next to the **Change…** button and defaults to the
  original path with `.fcrypt` appended (`report.pdf` → `report.pdf.fcrypt`).
  Decrypting strips `.fcrypt`, or appends `.decrypted` if the container did not
  have that extension.
- If the destination already exists, the app asks before replacing it.

### 2 · Create a password (encrypting)

Type a password twice, or press **Generate** (see
[the next section](#the-password-generator)). A strength meter gives advice but
never blocks you — the app will encrypt with `password123` if you insist, and the
Argon2id cost is what stands between that and an attacker.

### 2 · Enter the password (decrypting)

One field, no confirmation.

### 3 · Key derivation strength

How much work an attacker must do per guess:

| Preset | Argon2id memory | Passes | Lanes | Approx. time | Peak RAM |
|--------|----------------:|-------:|------:|-------------:|---------:|
| Standard | 64 MiB | 3 | 1 | 0.16 s | ~80 MB |
| High | 256 MiB | 4 | 2 | 0.37 s | ~270 MB |
| Paranoid | 512 MiB | 4 | 4 | 0.39 s | ~530 MB |

**Raising memory is what matters.** Memory is the resource an attacker cannot
manufacture cheaply; passes are comparatively easy to parallelise. The cost is
paid once per file, not per byte, so even Paranoid is unnoticeable on a large
file.

### Running

Press **Encrypt File** or **Decrypt File**. Progress is shown with the current
phase, and **Cancel** is available throughout — cancelling leaves nothing behind,
not even a partial file.

On success you get a green banner with **Show in Finder**. If you generated a
password, it is cleared from the window at this point, because the app does not
store it anywhere.

---

## The password generator

The weakest part of any password-based scheme is the password a human invents.
Press **Generate** in the password card and the app draws one from the system
CSPRNG instead.

### What it does

- **20 characters by default**, drawn from 80 possible characters.
- **Four character classes** — lower case, upper case, digits, symbols — with at
  least one of each guaranteed.
- **No look-alike characters.** `0`, `O`, `o`, `1`, `l` and `I` are excluded,
  because you will probably have to read this password off the screen and type it
  back in at some point. A password that cannot be re-entered is not a password,
  it is a data-loss incident.
- **Auto-revealed and auto-filled.** A password you cannot read is a password you
  cannot save, so generating reveals the field and fills the confirmation too.
- **A reminder to save it**, with a **Copy** button, because the app will not be
  able to show it again.

### Why the numbers are trustworthy

Two things in a naive generator quietly reduce the strength of everything it
produces:

**Modulo bias.** `randomByte % 80` is not uniform — 256 ÷ 80 leaves a remainder of
16, so the first 16 characters of the alphabet come up 33 % more often than the
rest. FileCrypt uses rejection sampling: bytes in the top remainder are discarded
and redrawn, which is provably uniform. A chi-square test over 62 000 samples
guards this.

**A biased "one of each class" shuffle.** The common trick of picking one
character from each class and shuffling the result does not produce a uniform
distribution over the valid passwords. FileCrypt instead generates a fully
uniform candidate and retries if it is missing a class, which keeps the output
uniform over exactly the set of passwords that satisfy the rule.

### Options

Available from the gear menu next to **Generate**, and from the CLI:

| Option | Default | Effect |
|--------|---------|--------|
| Length | 20 | 8–64 characters in the app, up to 256 in the CLI |
| Include symbols | on | Off limits the pool to letters and digits |
| Avoid look-alike characters | on | Off adds back `0 O o 1 l I` |
| Use every selected character type | on | Off drops the "one of each" guarantee |

### How strong is it

Entropy is `length × log2(pool size)`, where the default pool is 80 characters.

| Setting | Pool | Entropy |
|---------|-----:|--------:|
| 12 characters, all classes | 80 | 76 bits |
| 16 characters, all classes | 80 | 101 bits |
| **20 characters, all classes (default)** | **80** | **126 bits** |
| 24 characters, all classes | 80 | 152 bits |
| 32 characters, all classes | 80 | 202 bits |
| 20 characters, letters and digits | 56 | 116 bits |

For scale: a 5-word Diceware passphrase is about 65 bits, and an 8-character
random lower-case password is 38 bits. Nothing at 126 bits is reachable by
guessing — at a billion guesses a second against a 64 MiB Argon2id, exhausting a
126-bit space takes longer than the universe has existed.

The entropy shown in the app is `length × log2(pool)`, which is very slightly
generous because requiring one of every class conditions the distribution. At 20
characters the difference is about 0.0004 bits, so it is not worth confusing the
user with a second number.

### Copying

The **Copy** button puts the password on the system clipboard. FileCrypt does
**not** clear the clipboard afterwards — that would surprise you if you were
mid-paste, and macOS clipboard managers keep their own history anyway. If that
matters to you, clear it yourself.

---

## Using the command line

`fcrypt` mirrors the app and is useful for scripting.

```
fcrypt encrypt <input> <output> [options]
fcrypt decrypt <input> <output> [options]
fcrypt info     <input>
fcrypt generate [options]
fcrypt selftest
```

### Encryption and decryption

```bash
# Prompt for the password on the terminal, with echo off.
fcrypt encrypt report.pdf report.pdf.fcrypt
fcrypt decrypt report.pdf.fcrypt report.pdf

# Non-interactive password sources.
fcrypt encrypt --password-env FILE_PASSWORD in.bin out.fcrypt
fcrypt encrypt --password-file ~/.secret in.bin out.fcrypt
printf 'hunter2\n' | fcrypt encrypt --password-stdin in.bin out.fcrypt

# Raise the Argon2id cost.
fcrypt encrypt --memory 262144 --time-cost 4 --parallelism 2 in.bin out.fcrypt

# Tune framing for many small records (rarely worth changing).
fcrypt encrypt --chunk-size 65536 in.bin out.fcrypt

# Suppress the progress bar.
fcrypt encrypt --quiet --password pw in.bin out.fcrypt
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--password <pw>` | — | Inline password; visible in the process list |
| `--password-env <VAR>` | — | Read from an environment variable |
| `--password-file <path>` | — | First line of a file |
| `--password-stdin` | — | First line of standard input |
| `--memory <kib>` | 65536 | Argon2id memory cost, in KiB |
| `--time-cost <n>` | 3 | Argon2id passes, 1–64 |
| `--parallelism <n>` | 1 | Argon2id lanes, 1–16 |
| `--chunk-size <n>` | 1048576 | Plaintext bytes per record |
| `--quiet` | off | Suppress progress output |

With none of the password options, `fcrypt` prompts on the terminal with echo
disabled.

Numeric options are parsed strictly: `--memory 999999999999` is an error, not a
silent fall back to the default. Silently handing back a weaker file than the one
that was asked for would be the worst possible failure mode for this tool.

### Inspecting a container without decrypting it

```console
$ fcrypt info report.pdf.fcrypt
file:            /Users/you/report.pdf.fcrypt
container:       FileCrypt format 2
cipher:          AES-256-GCM (chunked, per-record AAD binding)
key derivation:  Argon2id, 64 MiB memory, 3 passes, 1 lane -> HKDF-SHA256
chunk size:      1048576 bytes
salt (hex):      1ca9e94736be8430a620d391368b7f0a47a3e63a421a55aaad703edbe975771c
container size:  314578888 bytes
payload size:    314578800 bytes
```

### Generating passwords

```bash
fcrypt generate                          # 20 characters, one line
fcrypt generate --length 32
fcrypt generate --length 24 --count 5    # five of them, one per line
fcrypt generate --no-symbols             # letters and digits only
fcrypt generate --allow-ambiguous        # keep 0/O/o, 1/l/I
fcrypt generate --quiet                  # no note on stderr
```

The passwords go to **stdout**, one per line, and the entropy note goes to
**stderr**, so this does what you would expect:

```bash
PW=$(fcrypt generate --length 32 --quiet)
fcrypt encrypt --password "$PW" secret.pdf secret.pdf.fcrypt
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--length <n>` | 20 | 8–256 characters |
| `--count <n>` | 1 | How many to print, 1–1000 |
| `--no-symbols` | off | Letters and digits only |
| `--allow-ambiguous` | off | Keep look-alike characters |
| `--no-required-classes` | off | Drop the "one of every type" rule |

### Self test

```bash
fcrypt selftest
```

Round-trips eight file sizes, checks that a wrong password is rejected, and
checks that a flipped bit is detected. Useful as a smoke test after building.

---

## How the encryption works

```
password
   │  NFC normalise, UTF-8 encode
   ▼
Argon2id · 64 MiB memory · 3 passes · 32-byte CSPRNG salt
   │
   ▼  32-byte master seed
HKDF-SHA256 ──┬─ info "FCRYPTv2/aes-256-gcm"    ──▶ AES-256 key
              └─ info "FCRYPTv2/key-commitment"  ──▶ commitment key
   │
   ▼
AES-256-GCM, one record per 1 MiB of plaintext
```

### Why Argon2id

It is **memory-hard**. A guess costs the attacker RAM bandwidth, not just CPU
cycles, and memory is the one resource GPUs and ASICs cannot manufacture cheaply.
PBKDF2 is the opposite: a tight HMAC loop that parallelises almost perfectly on a
graphics card, so a 600 000-round PBKDF2 hash is far weaker per unit of attacker
spend than it looks. Argon2id is the OWASP first choice and the RFC 9106
recommendation, and the `id` variant is the one that resists both side-channel and
time-memory-tradeoff attacks.

The implementation is the **PHC reference code**, vendored under `Sources/CArgon2`
rather than reimplemented. Hand-rolling a memory-hard KDF that nobody has reviewed
would be worse than leaving PBKDF2 in place.

### Why HKDF as well

Argon2id does the expensive work; HKDF then splits its 32-byte output into two
independent subkeys, because one output must not serve two purposes. The key that
authenticates the public header commitment must not be the key that protects the
file. HKDF's cost is nothing next to Argon2id's.

### Why a key commitment

The header carries `HMAC-SHA256(commitmentKey, header)`. A wrong password is
rejected with one constant-time comparison, before a single byte of ciphertext is
read — so a wrong password on a 300 GB file fails in 0.15 s rather than after
reading the whole thing.

### Why the file is chunked

AES-GCM is a one-shot AEAD; sealing a 20 GB file in memory is not an option. Each
1 MiB plaintext record is sealed separately, and every record's nonce and
additional authenticated data bind it to its position:

```
nonce for record i = 0x00000000 ‖ uint64be(i)
AAD   for record i = full header ‖ uint64be(i) ‖ isFinal ‖ uint32le(length)
```

That one construction makes the container tamper-evident in every direction:

| Attack | Why it fails |
|--------|--------------|
| Reorder records | Record 5 authenticates itself as record 5 |
| Truncate the file | The real last record was sealed with `isFinal = 1`; the new "last" record is verified with `isFinal = 0` |
| Append data | Same, in reverse: the genuine final record stops verifying |
| Edit the header | The header is inside every record's AAD |
| Edit a length prefix | The length is inside the AAD |
| Flip any ciphertext bit | GCM authentication tag |

Nonce reuse — the one thing that would be fatal for GCM — is impossible by
construction: the AES key derives from a fresh 32-byte CSPRNG salt on every
encryption, so any given key only ever seals one file's records, each with a
distinct index.

### Backwards compatibility

Containers written by earlier builds used PBKDF2 in a slightly different header
(called format 1). Those still open. The app reads format 1, reports it as legacy
in `fcrypt info`, and re-encrypts with Argon2id when you write the file again.
Nothing new is ever written as format 1.

---

## Container format

```
┌──────────────────────── header (88 or 96 bytes) ───────────────────────┐
│ magic │ ver │ kdf │ cipher │ flags │ chunk │ kdf params │ size │ salt │ commit │
└────────────────────────────────────────────────────────────────────────┘
┌─ record 0 ─┐┌─ record 1 ─┐                          ┌─ record N-1 ─┐
│ len │ ct ‖ tag │ len │ ct ‖ tag │ ...                │ len │ ct ‖ tag │
└─────┘         └─────┘                               └─────┘
```

| | Format 1 | Format 2 |
|---|---|---|
| magic | `FCRYPTv1` | `FCRYPTv2` |
| header size | 88 bytes | 96 bytes |
| key derivation | PBKDF2-HMAC-SHA512 | Argon2id |
| status | read-only | current |

The full byte-level specification, including the exact AAD construction and
known-answer vectors, is in **[`docs/FORMAT.md`](docs/FORMAT.md)**.

---

## Safety properties

- **Atomic output.** Everything is written to a hidden `.part` file in the
  destination folder and renamed into place only on success. A wrong password, a
  corrupt block, a full disk or a cancel leaves the destination untouched.
- **Constant memory.** Files are streamed one record at a time, so the footprint
  does not depend on file size. A 16 GiB file peaks at 85 MB, most of which is the
  Argon2id memory cost paid once during key derivation.
- **Nothing secret is persisted.** The password lives in memory for the length of
  the operation and the buffers the app owns are wiped afterwards. It is never
  written to disk, the keychain or a log.
- **Hostile input cannot hang the app.** The declared Argon2id parameters and
  chunk size are validated against hard bounds *before* anything is allocated, so
  a crafted container cannot make the app reserve 4 GiB or spin for an hour.
- **No sandbox entitlements beyond the file you picked.** The app is not sandboxed
  and asks for nothing; it only touches the paths you choose.

### Verification status

Everything above is tested, but two things are worth being explicit about:

- The GUI behaviour is covered by tests that drive the same code paths the buttons
  call, and the interface has been reviewed by rendering it. It has not been
  exhaustively driven by hand.
- The app is **ad-hoc signed**. It runs on the machine that built it. Copying it
  elsewhere requires a Developer ID signature and notarisation.

---

## What this does not protect against

- **A weak password.** Argon2id makes guessing expensive; it does not make it
  impossible. Use the generator, or a long unique passphrase.
- **A compromised Mac.** Malware running as you can read the plaintext before it
  is encrypted or after it is decrypted, and can read the password as you type it.
- **Losing the password.** There is no recovery, no backdoor and no escrow. If the
  password is gone, the file is gone.
- **Metadata.** The container reveals its size (rounded up by at most 4 bytes per
  MiB), and the original file's POSIX permissions are copied to the output. The
  original filename is not stored inside the container.
- **Rubber-hose cryptanalysis.** If someone can compel the password from you, the
  maths is irrelevant.

---

## Testing

```bash
swift test                # 114 tests
./Scripts/smoke.sh        # 83 black-box checks
./Scripts/largefile_check.sh --size 16G
```

If `swift build` fails with `sandbox-exec: sandbox_apply: Operation not
permitted`, you are already inside a sandbox that forbids nested sandboxing. Add
`--disable-sandbox`; `build.sh` detects this and retries automatically.

### Unit tests

| Suite | Tests | Covers |
|-------|------:|--------|
| `Argon2Tests` | 6 | Known-answer vectors from the reference `argon2` CLI, parameter bounds, memory cost actually dominating runtime |
| `KeyDerivationTests` | 12 | PBKDF2-SHA512 vectors, HKDF-SHA256 against RFC 5869, NFC normalisation, commitment verification |
| `FileCipherRoundTripTests` | 12 | Sizes straddling the chunk boundary, empty files, Unicode passwords, deterministic container layout |
| `FileCipherIntegrityTests` | 29 | Truncation at eight offsets, record reordering and replay, bit flips in *every* header byte, cancellation, permissions, temporary-file cleanup |
| `ByteCodingTests` | 6 | Exact byte order of the framing helpers |
| `InteropTests` | 9 | A golden container per format, produced by an independent implementation |
| `MemoryFootprintTests` | 2 | Memory does not scale with file size (4 MiB vs 48 MiB) — see the note below |
| `PasswordGeneratorTests` | 16 | Length, pool membership, class guarantees, look-alike exclusion, chi-square uniformity, entropy |
| `AppModelTests` | 22 | Mode switching, destination naming, validation, overwrite prompt, cancel, full round trip through the model |

### Interoperability

`Scripts/reference_fcrypt.py` is a from-scratch Python implementation of the
format that shares no code with the app:

```bash
python3 Scripts/reference_fcrypt.py encrypt in.bin out.fcrypt 'password'
python3 Scripts/reference_fcrypt.py decrypt out.fcrypt back.bin 'password'
python3 Scripts/reference_fcrypt.py info out.fcrypt
```

`InteropTests` embeds a container per format built by that script. For the current
Argon2id format it asserts both directions: Swift decrypts it, and Swift
re-encrypting the same input with the same salt and parameters reproduces it byte
for byte. For the legacy PBKDF2 format it asserts the container still opens.

This matters more than it sounds. A matching writer/reader pair can be
*self-consistently wrong* and round trip perfectly while being unreadable by
anything else. It caught exactly that during development: the 64-bit record index
was being written little-endian while the specification said big-endian. Because
record 0's index is all zeros, single-record files still interoperated — only
multi-record files were affected, and only against another implementation.
`ByteCodingTests` now pins the exact bytes.

### A note on the memory test

`MemoryFootprintTests` originally asserted that encrypting a 48 MiB file grew
resident memory by less than a fixed 20 MiB, and it was intermittently flaky —
about one run in ten failed reporting growth of exactly 48 MiB.

That was a defect in the *test*, not a leak. `task_info`'s `resident_size` counts
resident pages, and other suites in the same target allocate and release
multi-megabyte buffers before it runs (`AppModelTests` frees a 12 MiB
cancellation fixture). Those pages stay resident in the allocator's free list —
macOS only reclaims them under memory pressure — so the baseline already
contained them and their reuse was counted as growth.

The test now compares a 4 MiB file against a 48 MiB one and asserts the
*difference* is small. Allocator noise is a roughly fixed offset that cancels
out, while a missing autorelease pool brings back per-record accumulation that
cannot. Removing the pool still fails the test, with a message that names the
cause; twelve consecutive full runs are clean.

### Smoke suite

```bash
./Scripts/smoke.sh
```

83 black-box checks against the real binary: round trips at seven sizes, every
password source, password generation, the error paths (wrong password, missing
input, input equal to output, unparseable options), ten different tamperings of a
real container, and interoperability in both directions.

### Large files

```bash
./Scripts/largefile_check.sh --size 16G --chunk-size 1M
./Scripts/largefile_check.sh --size 50G            # needs ~100 GB free
```

The harness generates a file whose every 8 bytes encode their own offset, so the
data at byte *n* depends on *n* and nothing else — any skipped, duplicated or
misplaced region changes the bytes. It then encrypts, **deletes the plaintext**,
decrypts, and verifies the result against a *regenerated* stream, so peak disk use
is twice the file size rather than three times. It refuses to start without that
headroom.

Measured on an M-series Mac:

| File | Chunk | Records | Peak RSS | Result |
|------|-------|--------:|---------:|--------|
| 16 GiB | 1 MiB | 16 384 | 85 MB | byte-identical |
| 8 GiB | 128 KiB | 65 536 | 74 MB | byte-identical |
| 1 GiB | 1 MiB | 1 024 | 21 MB | byte-identical |

Two things are worth reading off that table.

**Memory does not track file size.** 16 GiB peaks at 85 MB, and about 64 MB of
that is the Argon2id cost, paid once and released. The stream itself contributes a
couple of MiB of buffers regardless of file size.

**The relevant boundary is 4 GiB, not 50 GiB.** The one way a large file breaks a
naive implementation is a 32-bit byte counter wrapping at 2³² = 4 GiB. Past that
there is no further representational cliff until 2⁶³, so a 16 GiB run already
crosses the only one; 50 GiB would add runtime, not coverage. The second run
covers the other dimension: at 128 KiB chunks, 65 536 records is more records than
a 50 GB file uses at the default 1 MiB, so the record-index path is exercised
beyond that scale too.

A literal 50 GB round trip additionally needs about 100 GB of free disk, because
the input and the container exist at the same time.

### Reproducing the UI without a display

```bash
./build/FileCrypt.app/Contents/MacOS/FileCrypt --render-preview /tmp/preview
```

Renders each interface state to a PNG and exits. It hosts the real view in an
`NSWindow` and captures it with `cacheDisplay(in:to:)` rather than using SwiftUI's
`ImageRenderer`, because `ImageRenderer` has its own rasteriser that cannot draw
AppKit-backed controls — text fields, segmented pickers and the drop zone come out
as yellow "unrenderable" blocks.

One caveat: the window never becomes key in a headless run, so AppKit draws
control chrome in its muted inactive style. A `.borderedProminent` button renders
grey there regardless of its tint (verified by rendering the same button tinted
red, yellow and untinted — all three come out identical), so the previews are
accurate for layout, content and state but not for accent colour.

---

## Project layout

```
Sources/FileCryptCore/          the engine — no UI, fully unit-tested
  FileCipher.swift                streaming encrypt/decrypt
  FileHeader.swift                container header, parse + validate
  KeyDerivation.swift             Argon2id/PBKDF2 → HKDF key schedule
  Argon2.swift                    Swift wrapper over the vendored reference Argon2
  PasswordGenerator.swift         unbiased CSPRNG password generation
  PasswordStrength.swift          advisory strength estimate
  PBKDF2.swift                    CommonCrypto wrapper (legacy format 1 only)
  OutputTransaction.swift         atomic writes
  ProgressReporter.swift          throttled progress callbacks
  ByteCoding.swift                explicit endian handling
  SecureData.swift                CSPRNG and buffer wiping
  CryptoError.swift               every failure the core can produce
  EncryptionOptions.swift         tunables and cancellation

Sources/FileCrypt/              the SwiftUI app
  FileCryptApp.swift              @main, app delegate
  ContentView.swift               the interface
  Theme.swift                     colour, metric and type tokens
  AppModel.swift                  state, validation, actions
  CryptRunner.swift               bridges the synchronous cipher to async
  DevPreview.swift                offscreen renderer (development only)

Sources/CArgon2/                vendored phc-winner-argon2, see NOTICE.md
Sources/fcrypt/                 the command-line tool
Tests/FileCryptCoreTests/       91 tests (engine)
Tests/FileCryptAppTests/        22 tests (app behaviour)
Scripts/smoke.sh                black-box end-to-end suite
Scripts/largefile_check.sh      large-file round trip
Scripts/counter_pattern.py      offset-encoding generator/verifier
Scripts/reference_fcrypt.py     independent format implementation
Scripts/make_icon.swift         renders the app icon from source
Resources/Info.plist            bundle metadata
docs/FORMAT.md                  byte-level format specification
```

---

## Troubleshooting

**"This file failed its integrity check."**
The container is damaged, truncated, or was modified after it was written. The
authentication tag covers the whole file, so this is not a false alarm. Restore
from a backup.

**"The password is incorrect, or the file has been modified."**
Exactly what it says. Argon2id is deterministic, so the same password on the same
container always works; if it does not, the password is wrong.

**"…is a folder. Choose a file name for the result, not a folder."**
The destination you picked is an existing directory. The app checks this before
doing any work, so nothing was encrypted.

**A filename beginning with a dash is rejected as an unknown option.**
Put `--` before the paths: `fcrypt encrypt --password pw -- ./--weird out.fcrypt`.

**Decryption is slow to start.**
That is Argon2id, and it is the point. 64 MiB and 3 passes takes about 0.16 s;
Paranoid takes about 0.4 s. It is paid once per file, not per byte.

**The app will not open on another Mac.**
It is ad-hoc signed. Sign with a Developer ID and notarise it to distribute.

**`swift build` fails with `sandbox_apply: Operation not permitted`.**
You are inside a sandbox that forbids nested sandboxing. Use
`swift build --disable-sandbox`, or just use `./build.sh`, which detects this.

**`swift test` cannot find a module.**
Run `./build.sh` first — it resolves the C target and the vendored Argon2.

---

## Development notes

- Requires macOS 14+ and Swift 6. No package dependencies: CryptoKit,
  CommonCrypto, Foundation, and a vendored copy of the reference Argon2.
- `Tests/FileCryptAppTests` imports the `FileCrypt` executable target directly,
  which SwiftPM supports for executables that use `@main` rather than top-level
  code.
- `Sources/CArgon2` is vendored upstream code, not this project's. It is
  deliberately unmodified; see `Sources/CArgon2/NOTICE.md` for provenance, licence
  and the exact file list.
- The icon is generated from source by `Scripts/make_icon.swift`. There are no
  binary art assets in the repository.

---

## Licence

FileCrypt is released under the **MIT License**. The full text is in
[`LICENSE`](LICENSE).

```
Copyright (c) 2026 Irshad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

In short: use it, modify it, ship it, sell it. Keep the copyright notice, and
understand that it comes with no warranty. That last part matters more than
usual here — **if you lose your password, nobody can recover your file, and that
is a design decision rather than a defect.**

Every source file this project owns carries an
`SPDX-License-Identifier: MIT` header. The built app ships the licence texts
inside itself, at `FileCrypt.app/Contents/Resources/Licenses/`.

## Attribution

FileCrypt bundles one piece of third-party code. Full details are in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

**Argon2** — `Sources/CArgon2/`, taken unmodified from
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) at tag
`20190702`.

```
Argon2 reference source code package - reference C implementations

Copyright 2015
Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves

You may use this work under the terms of a Creative Commons CC0 1.0
License/Waiver or the Apache Public License 2.0, at your option.
```

Argon2 won the [Password Hashing Competition](https://www.password-hashing.net/)
and is specified in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106). It is
used here under the CC0 option, which imposes no conditions; the full text of
both licences is in [`Sources/CArgon2/LICENSE`](Sources/CArgon2/LICENSE).

Everything else links only against Apple system frameworks that ship with macOS
— CryptoKit, CommonCrypto, Foundation, Security, AppKit and SwiftUI. No other
third-party code is bundled.
