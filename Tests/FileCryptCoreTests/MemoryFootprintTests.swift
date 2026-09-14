//
//  MemoryFootprintTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Darwin
import Foundation
import XCTest

@testable import FileCryptCore

/// Guards the streaming property that makes large files possible.
///
/// `FileHandle.read(upToCount:)` hands back autoreleased buffers. Without an
/// explicit pool per record those buffers accumulate for the whole run, and the
/// process grows to roughly the size of the file it is processing — a 1 GiB file
/// cost about 1 GiB of resident memory instead of about 20 MiB.
///
/// ## Why this measures two sizes rather than one
///
/// The first version of this test asserted that encrypting a 48 MiB file grew
/// resident memory by less than a fixed 20 MiB, and it was intermittently flaky:
/// roughly one run in ten failed reporting a growth of exactly 48 MiB.
///
/// The cause was not a leak. `task_info`'s `resident_size` counts *resident
/// pages*, and several other suites in this target allocate and release
/// multi-megabyte buffers before this one runs (`AppModelTests` alone frees a
/// 12 MiB cancellation fixture). Those pages stay resident in the allocator's
/// free list — macOS only reclaims them under memory pressure — so the
/// "baseline" already contains them and any later reuse is counted as growth.
///
/// The property that actually matters is that memory *scales* with the file, so
/// that is what is measured: a 48 MiB payload must not cost dramatically more
/// than a 4 MiB one. Residual allocator noise is a roughly fixed offset that
/// cancels out of the difference, while a missing autorelease pool brings back
/// per-record accumulation, which cannot cancel.
final class MemoryFootprintTests: TemporaryDirectoryTestCase {

    /// Current resident set size of this process, in bytes.
    private func residentMemoryBytes() -> UInt64? {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size
        )
        let status = withUnsafeMutablePointer(to: &info) { pointer -> kern_return_t in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), rebound, &count)
            }
        }
        guard status == KERN_SUCCESS else { return nil }
        return UInt64(info.resident_size)
    }

    private let options = EncryptionOptions(
        chunkSize: 1 << 20,
        memoryKiB: TestFormat.memoryKiB,
        timeCost: TestFormat.timeCost,
        parallelism: TestFormat.parallelism
    )

    /// Write a `megabytes`-sized fixture in pieces, so building it never holds a
    /// large buffer alive across the measurement that follows.
    private func writeFixture(megabytes: Int, to url: URL, seed: UInt64) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        for piece in 0..<megabytes {
            try handle.write(contentsOf: makePayload(byteCount: 1 << 20, seed: seed &+ UInt64(piece)))
        }
        try handle.close()
    }

    /// A 12× larger file must not cost 12× more memory.
    func testEncryptionMemoryDoesNotScaleWithFileSize() throws {
        func growth(megabytes: Int, label: String) throws -> Int64 {
            let source = path("enc-\(label).bin")
            let container = path("enc-\(label).fcrypt")
            try writeFixture(megabytes: megabytes, to: source, seed: 0x5EED_1234)

            guard let baseline = residentMemoryBytes() else {
                throw XCTSkip("task_info is unavailable in this environment")
            }

            try FileCipher.encryptFile(
                at: source,
                to: container,
                password: "memory-footprint-password",
                options: options
            )

            guard let peak = residentMemoryBytes() else {
                throw XCTSkip("task_info is unavailable in this environment")
            }

            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: container)
            return Int64(peak) - Int64(baseline)
        }

        let small = try growth(megabytes: 4, label: "small")
        let large = try growth(megabytes: 48, label: "large")

        XCTAssertLessThan(
            large - small,
            Int64(24 * 1_024 * 1_024),
            "a 48 MiB file cost \(large / 1_048_576) MiB against \(small / 1_048_576) MiB for a 4 MiB file — "
                + "memory is scaling with the file, so the per-record autorelease pool is probably missing"
        )
    }

    /// The same property for the decryption path, which has its own loop.
    func testDecryptionMemoryDoesNotScaleWithFileSize() throws {
        func growth(megabytes: Int, label: String) throws -> Int64 {
            let source = path("dec-\(label).bin")
            let container = path("dec-\(label).fcrypt")
            let restored = path("dec-\(label).out")
            try writeFixture(megabytes: megabytes, to: source, seed: 0xF00D_0000)

            try FileCipher.encryptFile(at: source, to: container, password: "pw", options: options)
            try? FileManager.default.removeItem(at: source)

            guard let baseline = residentMemoryBytes() else {
                throw XCTSkip("task_info is unavailable in this environment")
            }

            try FileCipher.decryptFile(at: container, to: restored, password: "pw")

            guard let peak = residentMemoryBytes() else {
                throw XCTSkip("task_info is unavailable in this environment")
            }

            try? FileManager.default.removeItem(at: container)
            try? FileManager.default.removeItem(at: restored)
            return Int64(peak) - Int64(baseline)
        }

        let small = try growth(megabytes: 4, label: "small")
        let large = try growth(megabytes: 48, label: "large")

        XCTAssertLessThan(
            large - small,
            Int64(24 * 1_024 * 1_024),
            "decryption memory is scaling with file size (4 MiB cost \(small / 1_048_576) MiB, "
                + "48 MiB cost \(large / 1_048_576) MiB)"
        )
    }
}
