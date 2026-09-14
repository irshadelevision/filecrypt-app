//
//  ByteCoding.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Explicit little/big endian helpers.
///
/// The container format is defined byte-by-byte so that it does not depend on
/// any host endianness, alignment, or on how Foundation happens to represent a
/// `Data` slice. Everything here works on plain `[UInt8]`.
enum ByteCoding {

    static func appendUInt32LE(_ value: UInt32, to bytes: inout [UInt8]) {
        // Normalise to the wanted byte order as a *number*, then dump its
        // native memory. Shifting by hand is a trap: `.bigEndian` already
        // byte-swaps, so shifting that value MSB-first reverses it back again.
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { bytes.append(contentsOf: $0) }
    }

    static func appendUInt64BE(_ value: UInt64, to bytes: inout [UInt8]) {
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { bytes.append(contentsOf: $0) }
    }

    static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        precondition(offset >= 0 && offset + 4 <= bytes.count, "Read out of bounds.")
        return UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}

extension Data {
    /// Append a little-endian `UInt32` (used for record framing).
    mutating func fcAppendUInt32LE(_ value: UInt32) {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(4)
        ByteCoding.appendUInt32LE(value, to: &bytes)
        append(contentsOf: bytes)
    }
}
