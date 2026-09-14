//
//  SecureData.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import Security

/// Small helpers for handling secret material.
///
/// Swift's `Data` and `Array` are copied freely by the runtime, so nothing here
/// can give a hard guarantee that a secret never lands in a stray heap copy.
/// What it *can* do is make sure we actively overwrite the buffers we own
/// instead of leaving the password sitting in memory until the allocator
/// happens to reuse the page.
enum SecureData {

    /// Cryptographically secure random bytes from the system CSPRNG.
    static func randomBytes(count: Int) throws -> Data {
        precondition(count >= 0, "Byte count must not be negative.")
        guard count > 0 else { return Data() }

        var bytes = [UInt8](repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            zero(&bytes)
            throw CryptoError.randomGenerationFailed
        }
        let result = Data(bytes)
        zero(&bytes)
        return result
    }

    /// Overwrite an integer buffer (`[UInt8]`, `[Int8]`, ...) in place.
    /// Best effort, but it defeats the "secret stays in a live buffer after we
    /// are done with it" problem.
    static func zero<T: FixedWidthInteger>(_ bytes: inout [T]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            memset(base, 0, buffer.count)
        }
    }

    /// Overwrite a `Data` value in place.
    static func zero(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            memset(base, 0, buffer.count)
        }
    }
}
