//
//  KeyDerivation.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import CryptoKit
import Foundation

/// The pair of symmetric keys derived from the user's password.
struct DerivedKeys {
    /// Encrypts and authenticates the file payload.
    let encryptionKey: SymmetricKey
    /// Authenticates the key commitment in the header.
    let commitmentKey: SymmetricKey
}

/// The password -> key chain.
///
/// ```
/// password (UTF-8, NFC)
///     |
///     |  Argon2id: memory-hard, 32-byte random salt
///     v
/// master seed (32 bytes)
///     |
///     +-- HKDF-SHA256(salt, info="FCRYPTv2/aes-256-gcm") ------> AES-256 key
///     |
///     +-- HKDF-SHA256(salt, info="FCRYPTv2/key-commitment") ---> commitment key
/// ```
///
/// Argon2id does the expensive work. HKDF then splits its output into two
/// independent subkeys, because a single 32-byte KDF output cannot safely be
/// used for two purposes: the key that computes the public header commitment
/// must not be the key that protects the file. HKDF's cost is negligible next
/// to Argon2id's.
///
/// The `info` labels are tied to the container format so that format 1 files,
/// which used PBKDF2 and the `FCRYPTv1` labels, keep deriving exactly the keys
/// they were written with.
enum KeyDerivation {

    /// Number of bytes fed into HKDF as input keying material.
    private static let masterSeedSize = 32
    /// AES-256 wants exactly 32 bytes.
    private static let keySize = 32

    static func deriveKeys(
        password: Data,
        salt: Data,
        parameters: KeyDerivationParameters
    ) throws -> DerivedKeys {
        guard !password.isEmpty else { throw CryptoError.emptyPassword }

        // The slow part. Everything after this is cheap.
        var seed: Data
        switch parameters {
        case .argon2id(let memoryKiB, let timeCost, let parallelism):
            seed = try Argon2.deriveKey(
                password: password,
                salt: salt,
                memoryKiB: memoryKiB,
                timeCost: timeCost,
                parallelism: parallelism,
                outputByteCount: masterSeedSize
            )
        case .pbkdf2SHA512(let iterations):
            seed = try PBKDF2.deriveSHA512(
                password: password,
                salt: salt,
                iterations: iterations,
                outputByteCount: masterSeedSize
            )
        }
        defer { SecureData.zero(&seed) }

        let label = parameters.format.hkdfLabel
        let master = SymmetricKey(data: seed)
        let encryptionKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: salt,
            info: Data("\(label)/aes-256-gcm".utf8),
            outputByteCount: keySize
        )
        let commitmentKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: salt,
            info: Data("\(label)/key-commitment".utf8),
            outputByteCount: keySize
        )
        return DerivedKeys(encryptionKey: encryptionKey, commitmentKey: commitmentKey)
    }

    /// Key commitment over the header prefix.
    static func commitment(for prefix: Data, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: prefix, using: key))
    }

    /// Constant-time verification of the key commitment.
    static func isValidCommitment(_ commitment: Data, prefix: Data, key: SymmetricKey) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(commitment, authenticating: prefix, using: key)
    }

    /// Turn a user-typed password into the bytes we actually derive from.
    ///
    /// The password is NFC-normalised first. Without that, "é" typed on macOS
    /// (one code point) and the same character typed on Windows (two code
    /// points) would produce different keys and the file would be unreadable
    /// after a copy/paste through another platform.
    static func normalisedPassword(_ password: String) throws -> Data {
        let normalised = password.precomposedStringWithCanonicalMapping
        guard let data = normalised.data(using: .utf8), !data.isEmpty else {
            throw CryptoError.emptyPassword
        }
        guard data.count <= EncryptionOptions.maximumPasswordByteCount else {
            throw CryptoError.passwordTooLong(max: EncryptionOptions.maximumPasswordByteCount)
        }
        return data
    }
}
