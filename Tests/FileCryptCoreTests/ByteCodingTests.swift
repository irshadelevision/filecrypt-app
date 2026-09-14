//
//  ByteCodingTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Pins the exact byte order of the framing helpers.
///
/// This is deliberately a byte-level test rather than a round-trip test: a
/// matching writer/reader pair can be *self-consistently wrong* and still round
/// trip perfectly, while being unreadable by every other implementation. The
/// original version of `appendUInt64BE` had exactly that bug — it byte-swapped
/// the value and then shifted it MSB-first, reversing it straight back to
/// little-endian. Every index-0 record still interopened (all-zero bytes look
/// the same either way), so only multi-record files were affected, and only
/// against another implementation.
final class ByteCodingTests: XCTestCase {

    func testAppendUInt32LEWritesLeastSignificantByteFirst() {
        var bytes: [UInt8] = []
        ByteCoding.appendUInt32LE(0x0102_0304, to: &bytes)
        XCTAssertEqual(bytes, [0x04, 0x03, 0x02, 0x01])
    }

    func testAppendUInt32LEHandlesBoundaries() {
        var zero: [UInt8] = []
        ByteCoding.appendUInt32LE(0, to: &zero)
        XCTAssertEqual(zero, [0, 0, 0, 0])

        var maximum: [UInt8] = []
        ByteCoding.appendUInt32LE(UInt32.max, to: &maximum)
        XCTAssertEqual(maximum, [0xFF, 0xFF, 0xFF, 0xFF])

        var one: [UInt8] = []
        ByteCoding.appendUInt32LE(1, to: &one)
        XCTAssertEqual(one, [0x01, 0x00, 0x00, 0x00])
    }

    func testAppendUInt64BEWritesMostSignificantByteFirst() {
        var one: [UInt8] = []
        ByteCoding.appendUInt64BE(1, to: &one)
        XCTAssertEqual(one, [0, 0, 0, 0, 0, 0, 0, 1])

        var value: [UInt8] = []
        ByteCoding.appendUInt64BE(0x0102_0304_0506_0708, to: &value)
        XCTAssertEqual(value, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        var zero: [UInt8] = []
        ByteCoding.appendUInt64BE(0, to: &zero)
        XCTAssertEqual(zero, [0, 0, 0, 0, 0, 0, 0, 0])

        var maximum: [UInt8] = []
        ByteCoding.appendUInt64BE(UInt64.max, to: &maximum)
        XCTAssertEqual(maximum, [UInt8](repeating: 0xFF, count: 8))
    }

    /// The two encoders must be inverses of the documented readers.
    func testReadUInt32LEInvertsAppendUInt32LE() {
        for value: UInt32 in [0, 1, 255, 256, 65_536, 16_777_215, UInt32.max] {
            var bytes: [UInt8] = []
            ByteCoding.appendUInt32LE(value, to: &bytes)
            XCTAssertEqual(ByteCoding.readUInt32LE(bytes, at: 0), value)
        }
    }

    /// A record index must encode identically to a plain big-endian integer,
    /// which is what a non-Swift implementation will assume.
    func testIndexEncodingMatchesPythonIntegerToBytesBig() {
        // (1).to_bytes(8, "big"), (258).to_bytes(8, "big"), ...
        let expectations: [UInt64: [UInt8]] = [
            0: [0, 0, 0, 0, 0, 0, 0, 0],
            1: [0, 0, 0, 0, 0, 0, 0, 1],
            258: [0, 0, 0, 0, 0, 0, 1, 2],
            65_537: [0, 0, 0, 0, 0, 1, 0, 1]
        ]
        for (value, expected) in expectations {
            var bytes: [UInt8] = []
            ByteCoding.appendUInt64BE(value, to: &bytes)
            XCTAssertEqual(bytes, expected, "index \(value) encoded incorrectly")
        }
    }

    func testDataExtensionMatchesTheArrayHelper() {
        var data = Data()
        data.fcAppendUInt32LE(0xAABB_CCDD)
        XCTAssertEqual([UInt8](data), [0xDD, 0xCC, 0xBB, 0xAA])
    }
}
