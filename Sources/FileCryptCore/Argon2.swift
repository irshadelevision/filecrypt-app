//
//  Argon2.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import CArgon2
import Foundation

/// Argon2id, via the vendored PHC reference implementation.
///
/// Argon2id is a *memory-hard* function: an attacker cannot trade memory for
/// time, so the cost of a guessing attack is dominated by RAM bandwidth rather
/// than by raw compute. That is what makes it a much better choice than PBKDF2
/// here — PBKDF2-HMAC is trivially parallelised on a GPU, and a 600 000-round
/// SHA-512 loop is cheap to accelerate. Argon2id is also the OWASP first
/// choice, and the `id` variant is the one they recommend because it resists
/// both side-channel and time-memory-tradeoff attacks.
///
/// This type is a thin marshalling layer. The algorithm itself is the reference
/// implementation; nothing here reimplements cryptography.
enum Argon2 {

    /// Bounds enforced before anything is allocated.
    ///
    /// The lower bounds are the reference implementation's own minimums. The
    /// upper bounds exist so a hostile file cannot make the app try to allocate
    /// an absurd amount of memory before authentication has happened.
    static let minimumMemoryKiB: UInt32 = 8
    static let maximumMemoryKiB: UInt32 = 2 * 1_024 * 1_024   // 2 GiB
    static let minimumTimeCost: UInt32 = 1
    static let maximumTimeCost: UInt32 = 64
    static let minimumParallelism: UInt32 = 1
    static let maximumParallelism: UInt32 = 16

    /// Argon2 requires the memory cost to cover at least eight blocks per lane.
    static func isMemorySufficient(memoryKiB: UInt32, parallelism: UInt32) -> Bool {
        memoryKiB >= 8 * parallelism
    }

    /// Derive `outputByteCount` bytes from `password` and `salt`.
    static func deriveKey(
        password: Data,
        salt: Data,
        memoryKiB: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        outputByteCount: Int
    ) throws -> Data {

        guard !password.isEmpty else { throw CryptoError.emptyPassword }
        guard !salt.isEmpty else {
            throw CryptoError.invalidParameter("The Argon2 salt must not be empty.")
        }
        guard memoryKiB >= minimumMemoryKiB, memoryKiB <= maximumMemoryKiB else {
            throw CryptoError.invalidParameter(
                "Argon2 memory cost must be between \(minimumMemoryKiB) KiB and \(maximumMemoryKiB) KiB."
            )
        }
        guard isMemorySufficient(memoryKiB: memoryKiB, parallelism: parallelism) else {
            throw CryptoError.invalidParameter(
                "Argon2 needs at least 8 KiB of memory per lane."
            )
        }
        guard timeCost >= minimumTimeCost, timeCost <= maximumTimeCost else {
            throw CryptoError.invalidParameter(
                "Argon2 time cost must be between \(minimumTimeCost) and \(maximumTimeCost)."
            )
        }
        guard parallelism >= minimumParallelism, parallelism <= maximumParallelism else {
            throw CryptoError.invalidParameter(
                "Argon2 parallelism must be between \(minimumParallelism) and \(maximumParallelism)."
            )
        }
        guard outputByteCount >= 4 else {
            throw CryptoError.invalidParameter("The Argon2 output must be at least 4 bytes.")
        }

        var output = [UInt8](repeating: 0, count: outputByteCount)

        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    argon2id_hash_raw(
                        timeCost,
                        memoryKiB,
                        parallelism,
                        passwordBytes.baseAddress,
                        password.count,
                        saltBytes.baseAddress,
                        salt.count,
                        outputBytes.baseAddress,
                        outputByteCount
                    )
                }
            }
        }

        guard status == ARGON2_OK.rawValue else {
            SecureData.zero(&output)
            throw CryptoError.argon2Failed(reason: message(for: status))
        }

        let result = Data(output)
        SecureData.zero(&output)
        return result
    }

    /// Turn a reference-implementation status code into something a user can
    /// act on. The interesting ones are the two failures that can actually
    /// happen on a real machine: not enough memory, and a thread that would not
    /// start.
    private static func message(for status: Int32) -> String {
        switch status {
        case ARGON2_MEMORY_ALLOCATION_ERROR.rawValue:
            return "Not enough free memory for the chosen Argon2 memory cost. Close some apps, or re-encrypt with a lower setting."
        case ARGON2_THREAD_FAIL.rawValue:
            return "A worker thread could not be started for the chosen Argon2 parallelism."
        case ARGON2_MEMORY_TOO_LITTLE.rawValue:
            return "The memory cost is below the Argon2 minimum."
        case ARGON2_MEMORY_TOO_MUCH.rawValue:
            return "The memory cost is above what Argon2 accepts on this machine."
        case ARGON2_TIME_TOO_SMALL.rawValue:
            return "The time cost is below the Argon2 minimum."
        case ARGON2_TIME_TOO_LARGE.rawValue:
            return "The time cost is above the Argon2 maximum."
        case ARGON2_LANES_TOO_FEW.rawValue:
            return "The parallelism is below the Argon2 minimum."
        case ARGON2_LANES_TOO_MANY.rawValue:
            return "The parallelism is above the Argon2 maximum."
        case ARGON2_SALT_TOO_SHORT.rawValue:
            return "The salt is shorter than Argon2 accepts."
        case ARGON2_OUTPUT_TOO_SHORT.rawValue, ARGON2_OUTPUT_TOO_LONG.rawValue:
            return "The requested key length is outside what Argon2 accepts."
        default:
            return "The Argon2 implementation reported status \(status)."
        }
    }
}
