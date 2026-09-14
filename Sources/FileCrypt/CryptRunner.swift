//
//  CryptRunner.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import FileCryptCore
import Foundation

/// Named work factors offered in the UI.
enum KeyStrengthPreset: String, CaseIterable, Identifiable {
    case standard
    case high
    case paranoid

    var id: String { rawValue }

    /// Argon2id memory cost in KiB: the parameter that actually matters.
    ///
    /// Standard is the second parameter set recommended by RFC 9106. Above that
    /// the returns are real but modest, so the presets stay practical: measured
    /// on an M-series Mac they cost about 0.16 s, 0.37 s and 0.39 s.
    var memoryKiB: UInt32 {
        switch self {
        case .standard: return 64 * 1_024    // 64 MiB
        case .high: return 256 * 1_024       // 256 MiB
        case .paranoid: return 512 * 1_024   // 512 MiB
        }
    }

    /// Passes over that memory.
    var timeCost: UInt32 {
        switch self {
        case .standard: return 3
        case .high: return 4
        case .paranoid: return 4
        }
    }

    /// Lanes. More lanes use more cores for the same total memory.
    var parallelism: UInt32 {
        switch self {
        case .standard: return 1
        case .high: return 2
        case .paranoid: return 4
        }
    }

    var title: String {
        switch self {
        case .standard: return "Standard"
        case .high: return "High"
        case .paranoid: return "Paranoid"
        }
    }

    var detail: String {
        let megabytes = Double(memoryKiB) / 1_024
        let memory = megabytes.formatted(.number.precision(.fractionLength(0)))
        let lanes = parallelism == 1 ? "lane" : "lanes"
        return "Argon2id · \(memory) MiB memory · \(timeCost) passes · \(parallelism) \(lanes)"
    }
}

/// Runs the synchronous cipher off the main actor and bridges the result back.
enum CryptRunner {

    static func encrypt(
        input: URL,
        output: URL,
        password: String,
        options: EncryptionOptions,
        cancellation: CancellationFlag,
        progress: @escaping @Sendable (Double) -> Void,
        phase: @escaping @Sendable (FileCipherPhase) -> Void
    ) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let url = try FileCipher.encryptFile(
                        at: input,
                        to: output,
                        password: password,
                        options: options,
                        cancellation: cancellation,
                        progress: progress,
                        phase: phase
                    )
                    continuation.resume(returning: url)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    static func decrypt(
        input: URL,
        output: URL,
        password: String,
        cancellation: CancellationFlag,
        progress: @escaping @Sendable (Double) -> Void,
        phase: @escaping @Sendable (FileCipherPhase) -> Void
    ) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let url = try FileCipher.decryptFile(
                        at: input,
                        to: output,
                        password: password,
                        cancellation: cancellation,
                        progress: progress,
                        phase: phase
                    )
                    continuation.resume(returning: url)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
