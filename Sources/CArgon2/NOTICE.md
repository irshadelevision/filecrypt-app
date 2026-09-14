# Vendored: phc-winner-argon2

This directory contains the reference implementation of **Argon2**, the winner
of the Password Hashing Competition, taken unmodified from
<https://github.com/P-H-C/phc-winner-argon2> at tag `20190702`.

It is vendored rather than fetched as a package dependency so that FileCrypt
still builds with no network access and no third-party resolution step. It is
*not* code written for this project, and it should not be edited: to update it,
re-copy the files listed below from the upstream tag.

Files taken:

```
LICENSE
include/argon2.h
src/argon2.c
src/core.c
src/core.h
src/encoding.c
src/encoding.h
src/ref.c
src/thread.c
src/thread.h
src/blake2/blake2.h
src/blake2/blake2b.c
src/blake2/blake2-impl.h
src/blake2/blamka-round-ref.h
src/blake2/blamka-round-opt.h
```

## Licence

Upstream is dual-licensed **CC0 1.0 Universal** and **Apache License 2.0**; see
`LICENSE` in this directory for the full text. FileCrypt uses it under those
terms.

## What FileCrypt uses

`argon2id_hash_raw()` only — the raw-tag variant, so this project controls its
own salt, parameter encoding and key schedule rather than storing the upstream
`$argon2id$v=19$m=...,t=...,p=...$salt$hash` string format. The encoding, CLI and
library-string helpers are compiled in but unused.
