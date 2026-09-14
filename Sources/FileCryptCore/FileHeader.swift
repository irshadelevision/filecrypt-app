//
//  FileHeader.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// A FileCrypt container generation.
///
/// Everything layout-related hangs off this: the magic bytes, the header size,
/// and how much of the header the key commitment authenticates. Deriving the
/// layout from one value — rather than storing a `(version, kdf)` pair — makes
/// an inconsistent combination impossible to construct.
public enum ContainerFormat: UInt8, Sendable, CaseIterable {

    /// Format 1 — PBKDF2-HMAC-SHA512.
    ///
    /// Read-only legacy support, so containers written by earlier builds still
    /// open. Nothing new is written with it.
    case pbkdf2SHA512 = 1

    /// Format 2 — Argon2id, the current scheme.
    case argon2id = 2

    public var magic: [UInt8] {
        switch self {
        case .pbkdf2SHA512: return Array("FCRYPTv1".utf8)
        case .argon2id: return Array("FCRYPTv2".utf8)
        }
    }

    /// The `kdf` byte stored in the header.
    public var kdfIdentifier: UInt8 { rawValue }

    /// Total header size for this format.
    public var encodedSize: Int {
        switch self {
        case .pbkdf2SHA512: return 88
        case .argon2id: return 96
        }
    }

    /// Bytes covered by the key commitment — everything before it.
    public var prefixSize: Int {
        switch self {
        case .pbkdf2SHA512: return 56
        case .argon2id: return 64
        }
    }

    /// HKDF domain-separation label, tied to the format so that format 1 files
    /// keep deriving exactly the keys they were written with.
    var hkdfLabel: String { "FCRYPTv\(rawValue)" }

    /// The format a header starts with, or `nil` if it is not one of ours.
    public static func forMagic(_ bytes: [UInt8]) -> ContainerFormat? {
        let prefix = Array(bytes.prefix(8))
        return allCases.first { prefix == $0.magic }
    }
}

/// Which key-derivation function a container uses, and with what parameters.
public enum KeyDerivationParameters: Equatable, Sendable {

    /// PBKDF2-HMAC-SHA512, format 1. Legacy; read-only.
    case pbkdf2SHA512(iterations: UInt32)

    /// Argon2id, format 2. The current scheme.
    case argon2id(memoryKiB: UInt32, timeCost: UInt32, parallelism: UInt32)

    public var format: ContainerFormat {
        switch self {
        case .pbkdf2SHA512: return .pbkdf2SHA512
        case .argon2id: return .argon2id
        }
    }

    /// Human-readable summary, used by the UI and by `fcrypt info`.
    public var summary: String {
        switch self {
        case .pbkdf2SHA512(let iterations):
            return "PBKDF2-HMAC-SHA512, \(iterations.formatted(.number.grouping(.automatic))) rounds"
        case .argon2id(let memoryKiB, let timeCost, let parallelism):
            let megabytes = Double(memoryKiB) / 1_024
            let memory = megabytes >= 1
                ? "\(megabytes.formatted(.number.precision(.fractionLength(0)))) MiB"
                : "\(memoryKiB) KiB"
            let lanes = parallelism == 1 ? "lane" : "lanes"
            return "Argon2id, \(memory) memory, \(timeCost) pass\(timeCost == 1 ? "" : "es"), \(parallelism) \(lanes)"
        }
    }
}

/// The FileCrypt container header.
///
/// ## Format 2 (current, Argon2id) — 96 bytes
///
/// | offset | size | field       | value                                  |
/// |--------|------|-------------|----------------------------------------|
/// | 0      | 8    | magic       | `"FCRYPTv2"`                           |
/// | 8      | 1    | format      | `2`                                    |
/// | 9      | 1    | kdf         | `2` = Argon2id                         |
/// | 10     | 1    | cipher      | `1` = AES-256-GCM                      |
/// | 11     | 1    | flags       | `0`, reserved; unknown bits are fatal  |
/// | 12     | 4    | chunk size  | plaintext bytes per record             |
/// | 16     | 4    | memory      | Argon2id memory cost, KiB              |
/// | 20     | 4    | time cost   | Argon2id passes                        |
/// | 24     | 4    | parallelism | Argon2id lanes                         |
/// | 28     | 4    | header size | `96`                                   |
/// | 32     | 32   | salt        | CSPRNG salt                            |
/// | 64     | 32   | commitment  | HMAC-SHA256 over bytes `0..<64`        |
///
/// ## Format 1 (legacy, read-only) — 88 bytes
///
/// Same shape, but the four KDF-parameter bytes at offsets 16…19 hold a PBKDF2
/// iteration count, the header size is `88`, the salt starts at 24 and the
/// commitment covers bytes `0..<56`.
///
/// The commitment is a *key commitment*: one constant-time HMAC that rejects a
/// wrong password immediately, before any ciphertext is authenticated.
public struct FileHeader: Equatable, Sendable {

    public static let saltSize = 32
    public static let commitmentSize = 32

    /// AES-GCM authentication tag length in bytes.
    public static let tagSize = 16
    /// AES-GCM nonce length in bytes.
    public static let nonceSize = 12

    /// Cipher identifier for AES-256-GCM.
    public static let cipherIdentifier: UInt8 = 1

    // Sanity bounds. A hostile file must not be able to make us allocate
    // gigabytes or spin for minutes before it fails authentication.
    public static let minimumChunkSize: UInt32 = 1_024
    public static let maximumChunkSize: UInt32 = 16 * 1_024 * 1_024
    public static let minimumPBKDF2Iterations: UInt32 = 1_000
    public static let maximumPBKDF2Iterations: UInt32 = 20_000_000

    public var flags: UInt8
    public var chunkSize: UInt32
    public var salt: Data
    public var commitment: Data
    public var keyDerivation: KeyDerivationParameters

    public var format: ContainerFormat { keyDerivation.format }
    /// Total serialised size of this header.
    public var encodedSize: Int { format.encodedSize }
    /// Bytes the key commitment authenticates.
    public var prefixSize: Int { format.prefixSize }

    public init(
        chunkSize: UInt32,
        salt: Data,
        commitment: Data,
        keyDerivation: KeyDerivationParameters,
        flags: UInt8 = 0
    ) {
        self.flags = flags
        self.chunkSize = chunkSize
        self.salt = salt
        self.commitment = commitment
        self.keyDerivation = keyDerivation
    }

    /// The bytes the key commitment authenticates: everything before it.
    public func prefixBytes() -> Data {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(prefixSize)

        bytes.append(contentsOf: format.magic)
        bytes.append(format.rawValue)
        bytes.append(format.kdfIdentifier)
        bytes.append(FileHeader.cipherIdentifier)
        bytes.append(flags)
        ByteCoding.appendUInt32LE(chunkSize, to: &bytes)

        switch keyDerivation {
        case .pbkdf2SHA512(let iterations):
            ByteCoding.appendUInt32LE(iterations, to: &bytes)
        case .argon2id(let memoryKiB, let timeCost, let parallelism):
            ByteCoding.appendUInt32LE(memoryKiB, to: &bytes)
            ByteCoding.appendUInt32LE(timeCost, to: &bytes)
            ByteCoding.appendUInt32LE(parallelism, to: &bytes)
        }

        ByteCoding.appendUInt32LE(UInt32(encodedSize), to: &bytes)
        bytes.append(contentsOf: salt)

        precondition(
            bytes.count == prefixSize,
            "header prefix is \(bytes.count) bytes, expected \(prefixSize)"
        )
        return Data(bytes)
    }

    /// The full header, ready to be written to disk.
    public func encoded() -> Data {
        var bytes = [UInt8](prefixBytes())
        bytes.append(contentsOf: commitment)
        precondition(bytes.count == encodedSize, "header is \(bytes.count) bytes, expected \(encodedSize)")
        return Data(bytes)
    }

    /// Is this the start of a container this app understands?
    ///
    /// Lets a file that is not ours become "not a FileCrypt file" rather than a
    /// confusing parse error.
    public static func isFileCryptMagic(_ bytes: [UInt8]) -> Bool {
        ContainerFormat.forMagic(bytes) != nil
    }

    /// Parse and fully validate a header.
    ///
    /// Every rejection happens here, before a single byte of ciphertext is
    /// touched, so a malformed file never gets partway through decryption.
    public static func decode(_ data: Data) throws -> FileHeader {
        let bytes = [UInt8](data)

        guard let format = ContainerFormat.forMagic(bytes) else {
            throw CryptoError.notEncryptedFile
        }

        let expectedSize = format.encodedSize
        guard bytes.count == expectedSize else {
            throw CryptoError.corruptedFile(
                reason: "The header is \(bytes.count) bytes; format \(format.rawValue) headers are \(expectedSize)."
            )
        }
        guard bytes[8] == format.rawValue else {
            throw CryptoError.unsupportedFormat(
                reason: "the header declares version \(bytes[8]) but its magic bytes say \(format.rawValue)."
            )
        }
        guard bytes[9] == format.kdfIdentifier else {
            throw CryptoError.unsupportedFormat(reason: "unknown key-derivation scheme \(bytes[9]).")
        }
        guard bytes[10] == cipherIdentifier else {
            throw CryptoError.unsupportedFormat(reason: "unknown cipher \(bytes[10]).")
        }
        guard bytes[11] == 0 else {
            throw CryptoError.unsupportedFormat(
                reason: "unknown header flags (0x\(String(bytes[11], radix: 16)))."
            )
        }

        let chunkSize = ByteCoding.readUInt32LE(bytes, at: 12)
        guard chunkSize >= minimumChunkSize, chunkSize <= maximumChunkSize else {
            throw CryptoError.corruptedFile(
                reason: "The declared chunk size (\(chunkSize) bytes) is outside the supported range."
            )
        }

        let parameters: KeyDerivationParameters
        let declaredHeaderSize: UInt32

        switch format {
        case .pbkdf2SHA512:
            let iterations = ByteCoding.readUInt32LE(bytes, at: 16)
            declaredHeaderSize = ByteCoding.readUInt32LE(bytes, at: 20)
            guard iterations >= minimumPBKDF2Iterations, iterations <= maximumPBKDF2Iterations else {
                throw CryptoError.corruptedFile(
                    reason: "The declared work factor (\(iterations) rounds) is outside the supported range."
                )
            }
            parameters = .pbkdf2SHA512(iterations: iterations)

        case .argon2id:
            let memoryKiB = ByteCoding.readUInt32LE(bytes, at: 16)
            let timeCost = ByteCoding.readUInt32LE(bytes, at: 20)
            let parallelism = ByteCoding.readUInt32LE(bytes, at: 24)
            declaredHeaderSize = ByteCoding.readUInt32LE(bytes, at: 28)

            guard memoryKiB >= Argon2.minimumMemoryKiB, memoryKiB <= Argon2.maximumMemoryKiB else {
                throw CryptoError.corruptedFile(
                    reason: "The declared Argon2 memory cost (\(memoryKiB) KiB) is outside the supported range."
                )
            }
            guard timeCost >= Argon2.minimumTimeCost, timeCost <= Argon2.maximumTimeCost else {
                throw CryptoError.corruptedFile(
                    reason: "The declared Argon2 time cost (\(timeCost)) is outside the supported range."
                )
            }
            guard parallelism >= Argon2.minimumParallelism, parallelism <= Argon2.maximumParallelism else {
                throw CryptoError.corruptedFile(
                    reason: "The declared Argon2 parallelism (\(parallelism)) is outside the supported range."
                )
            }
            guard Argon2.isMemorySufficient(memoryKiB: memoryKiB, parallelism: parallelism) else {
                throw CryptoError.corruptedFile(
                    reason: "The declared Argon2 memory cost is below the 8 KiB per lane minimum."
                )
            }
            parameters = .argon2id(memoryKiB: memoryKiB, timeCost: timeCost, parallelism: parallelism)
        }

        guard declaredHeaderSize == UInt32(expectedSize) else {
            throw CryptoError.unsupportedFormat(
                reason: "the header declares a size of \(declaredHeaderSize) bytes; format \(format.rawValue) uses \(expectedSize)."
            )
        }

        let saltOffset = format.prefixSize - saltSize
        return FileHeader(
            chunkSize: chunkSize,
            salt: Data(bytes[saltOffset..<format.prefixSize]),
            commitment: Data(bytes[format.prefixSize..<expectedSize]),
            keyDerivation: parameters
        )
    }
}
