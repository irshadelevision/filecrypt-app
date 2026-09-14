//
//  TemporaryDirectoryTestCase.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Shared scaffolding: every test gets a private scratch directory that is
/// removed afterwards, so tests never interfere with each other.
class TemporaryDirectoryTestCase: XCTestCase {

    private(set) var scratch: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("FileCryptTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratch, FileManager.default.fileExists(atPath: scratch.path) {
            try? FileManager.default.removeItem(at: scratch)
        }
        scratch = nil
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    func path(_ name: String) -> URL {
        scratch.appendingPathComponent(name)
    }

    /// Deterministic, non-compressible pseudo-random bytes (xorshift64*).
    func makePayload(byteCount: Int, seed: UInt64 = 0x9E37_79B9_7F4A_7C15) -> Data {
        guard byteCount > 0 else { return Data() }
        var state = seed == 0 ? 1 : seed
        var bytes = [UInt8](repeating: 0, count: byteCount)
        for index in 0..<byteCount {
            state ^= state >> 12
            state ^= state << 25
            state ^= state >> 27
            bytes[index] = UInt8(truncatingIfNeeded: state &* 0x2545_F491_4F6C_DD1D)
        }
        return Data(bytes)
    }

    @discardableResult
    func write(_ data: Data, to url: URL) throws -> URL {
        try data.write(to: url)
        return url
    }
}

extension Data {
    /// Hex string, for readable failure messages.
    var hexDescription: String {
        map { String(format: "%02x", $0) }.joined()
    }

    func flippedBit(at index: Int) -> Data {
        var copy = self
        copy[index] ^= 0x01
        return copy
    }
}
