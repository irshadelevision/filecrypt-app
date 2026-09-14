# Third-party notices

FileCrypt itself is licensed under the MIT License — see [`../LICENSE`](../LICENSE).

It bundles one piece of third-party code, which remains under its own licence.

---

## Argon2

**Location:** `Sources/CArgon2/`
**Upstream:** <https://github.com/P-H-C/phc-winner-argon2>
**Version:** tag `20190702`
**Licence:** Creative Commons CC0 1.0 Universal **or** Apache License 2.0, at
your option. The full text of both is reproduced in
[`../Sources/CArgon2/LICENSE`](../Sources/CArgon2/LICENSE).

```
Argon2 reference source code package - reference C implementations

Copyright 2015
Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves

You may use this work under the terms of a Creative Commons CC0 1.0
License/Waiver or the Apache Public License 2.0, at your option.
```

Argon2 is the winner of the [Password Hashing
Competition](https://www.password-hashing.net/) and is specified in
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106).

### How FileCrypt uses it

FileCrypt calls `argon2id_hash_raw()` and nothing else. It uses the raw-tag entry
point so that this project controls its own salt, parameter encoding and key
schedule, rather than storing the upstream `$argon2id$v=19$m=...,t=...,p=...$`
string format. The encoding, CLI and library-string helpers are compiled in but
unused.

The source is vendored unmodified. To update it, re-copy the files listed in
[`../Sources/CArgon2/NOTICE.md`](../Sources/CArgon2/NOTICE.md) from the upstream
tag.

### Compatibility

CC0 1.0 imposes no conditions at all, so redistributing Argon2 alongside
MIT-licensed code is unproblematic. Apache 2.0 is likewise compatible with MIT
for this purpose; the combination is used here under the CC0 option.

---

## Everything else

No other third-party code is bundled. FileCrypt links only against Apple system
frameworks that ship with macOS:

| Framework | Used for |
|-----------|----------|
| CryptoKit | AES-256-GCM, HKDF-SHA256, HMAC-SHA256 |
| CommonCrypto | PBKDF2-HMAC-SHA512 (legacy format 1 reading only) |
| Foundation | File I/O, `FileHandle`, run loop |
| Security | `SecRandomCopyBytes` |
| AppKit / SwiftUI | the interface |

The verification scripts under `Scripts/` are development tooling and are not
part of any distributed binary. `Scripts/reference_fcrypt.py` optionally uses
the Python `cryptography` package and `libargon2`; neither is bundled.
