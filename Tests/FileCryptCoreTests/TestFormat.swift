//
//  TestFormat.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Foundation

@testable import FileCryptCore

/// Facts about the *current* container format that the tests need.
///
/// The production code deliberately has no "the header is N bytes" constant any
/// more — the size belongs to the format, and different formats differ — so the
/// tests pin it here instead. If the format ever changes, these tests should
/// fail loudly rather than silently following along.
enum TestFormat {

    /// Format 2, Argon2id.
    static let current = ContainerFormat.argon2id

    static var headerSize: Int { current.encodedSize }
    static var prefixSize: Int { current.prefixSize }
    static var magic: [UInt8] { current.magic }

    /// Fast Argon2id parameters, for tests that only care about framing.
    static let memoryKiB: UInt32 = 1_024
    static let timeCost: UInt32 = 1
    static let parallelism: UInt32 = 1

    /// A cheap options value mirroring `EncryptionOptions.testing`.
    static func options(chunkSize: Int = 4_096) -> EncryptionOptions {
        EncryptionOptions(
            chunkSize: chunkSize,
            memoryKiB: memoryKiB,
            timeCost: timeCost,
            parallelism: parallelism
        )
    }
}
