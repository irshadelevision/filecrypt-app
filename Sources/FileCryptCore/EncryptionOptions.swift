//
//  EncryptionOptions.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Tunables for a single encryption run.
public struct EncryptionOptions: Sendable {

    /// Plaintext bytes per AEAD record.
    public var chunkSize: Int
    /// Argon2id memory cost, in KiB. This is the parameter that matters most.
    public var memoryKiB: UInt32
    /// Argon2id number of passes over the memory.
    public var timeCost: UInt32
    /// Argon2id lanes. More lanes use more cores but the same total memory.
    public var parallelism: UInt32

    /// Plaintext bytes per record, when the caller does not choose one.
    public static let defaultChunkSize = 1 << 20

    /// 64 MiB of memory, 3 passes, single lane.
    ///
    /// This is comfortably above the OWASP minimum (19 MiB, t=2, p=1) and is
    /// the parameter set most projects settle on. Raising the memory cost is
    /// far more valuable than raising the pass count: it is the memory, not the
    /// repetition, that makes parallel hardware attacks expensive.
    public static let defaultMemoryKiB: UInt32 = 64 * 1_024
    public static let defaultTimeCost: UInt32 = 3
    public static let defaultParallelism: UInt32 = 1

    /// Longest password accepted, in UTF-8 bytes. Guards against a caller
    /// handing us something pathological to hash.
    public static let maximumPasswordByteCount = 4_096

    public init(
        chunkSize: Int = EncryptionOptions.defaultChunkSize,
        memoryKiB: UInt32 = EncryptionOptions.defaultMemoryKiB,
        timeCost: UInt32 = EncryptionOptions.defaultTimeCost,
        parallelism: UInt32 = EncryptionOptions.defaultParallelism
    ) {
        self.chunkSize = chunkSize
        self.memoryKiB = memoryKiB
        self.timeCost = timeCost
        self.parallelism = parallelism
    }

    /// The container parameters these options describe.
    public var keyDerivation: KeyDerivationParameters {
        .argon2id(memoryKiB: memoryKiB, timeCost: timeCost, parallelism: parallelism)
    }

    /// A cheap preset used by the test-suite.
    ///
    /// Deliberately weak: the tests need to prove the *format* and the framing
    /// are correct, and paying a real Argon2id cost on every one of them would
    /// make the suite unusably slow. Production paths never see this.
    static var testing: EncryptionOptions {
        EncryptionOptions(
            chunkSize: 4_096,
            memoryKiB: 1_024,
            timeCost: 1,
            parallelism: 1
        )
    }
}

/// Coarse progress phase, so the UI can explain the silent key-derivation pause.
public enum FileCipherPhase: Sendable {
    case derivingKey
    case processing
    case finalizing
}

/// A thread-safe "please stop" flag.
///
/// `Task.isCancelled` is only readable from inside an async context, but the
/// cipher runs synchronously on a worker thread, so cancellation is passed in
/// explicitly instead. That also lets the UI cancel without owning the task.
public final class CancellationFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    public init() {}

    public func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}
