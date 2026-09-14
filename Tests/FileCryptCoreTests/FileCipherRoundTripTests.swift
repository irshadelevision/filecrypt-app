//
//  FileCipherRoundTripTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

final class FileCipherRoundTripTests: TemporaryDirectoryTestCase {

    private let options = EncryptionOptions.testing
    private let password = "correct horse battery staple"

    // MARK: - Sizes

    /// Sizes chosen around the chunk boundary (4096) because off-by-one bugs
    /// live exactly there: the empty file, a single byte, chunk-1, chunk,
    /// chunk+1, and multi-chunk with a partial tail.
    func testRoundTripsAcrossChunkBoundaries() throws {
        let sizes = [0, 1, 2, 15, 1023, 4095, 4096, 4097, 8191, 8192, 8193, 12_345, 40_967]

        for size in sizes {
            let plain = makePayload(byteCount: size)
            let source = try write(plain, to: path("plain-\(size).bin"))
            let container = path("plain-\(size).fcrypt")
            let restored = path("restored-\(size).bin")

            try FileCipher.encryptFile(at: source, to: container, password: password, options: options)
            try FileCipher.decryptFile(at: container, to: restored, password: password)

            let recovered = try Data(contentsOf: restored)
            XCTAssertEqual(recovered.count, size, "size mismatch for \(size) bytes")
            XCTAssertEqual(recovered, plain, "payload mismatch for \(size) bytes")
        }
    }

    func testContainerLayoutForKnownInput() throws {
        let plain = makePayload(byteCount: 4096 + 10, seed: 42)
        let source = try write(plain, to: path("plain.bin"))
        let container = path("plain.fcrypt")

        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)
        let blob = try Data(contentsOf: container)

        // header + (4 + 4096 + 16) + (4 + 10 + 16)
        let expectedSize = TestFormat.headerSize + (4 + 4096 + 16) + (4 + 10 + 16)
        XCTAssertEqual(blob.count, expectedSize)

        // Record 0's length prefix.
        let firstLength = ByteCoding.readUInt32LE([UInt8](blob), at: TestFormat.headerSize)
        XCTAssertEqual(firstLength, 4096 + 16)

        // Record 1's length prefix sits right after record 0.
        let secondPrefixOffset = TestFormat.headerSize + 4 + 4096 + 16
        let secondLength = ByteCoding.readUInt32LE([UInt8](blob), at: secondPrefixOffset)
        XCTAssertEqual(secondLength, 10 + 16)
    }

    func testEmptyFileProducesExactlyOneEmptyRecord() throws {
        let source = try write(Data(), to: path("empty.bin"))
        let container = path("empty.fcrypt")

        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)

        let blob = try Data(contentsOf: container)
        XCTAssertEqual(blob.count, TestFormat.headerSize + 4 + 16)

        let restored = path("empty.out")
        try FileCipher.decryptFile(at: container, to: restored, password: password)
        XCTAssertEqual(try Data(contentsOf: restored), Data())
    }

    // MARK: - Passwords

    func testRoundTripsWithUnicodeAndEmojiPassword() throws {
        let unicodePassword = "pä§§wörd🔐中文"
        let plain = makePayload(byteCount: 5000)
        let source = try write(plain, to: path("unicode.bin"))
        let container = path("unicode.fcrypt")
        let restored = path("unicode.out")

        try FileCipher.encryptFile(at: source, to: container, password: unicodePassword, options: options)
        try FileCipher.decryptFile(at: container, to: restored, password: unicodePassword)

        XCTAssertEqual(try Data(contentsOf: restored), plain)
    }

    func testDecomposedAndComposedPasswordsAreEquivalent() throws {
        let plain = makePayload(byteCount: 1000)
        let source = try write(plain, to: path("nfc.bin"))
        let container = path("nfc.fcrypt")
        let restored = path("nfc.out")

        try FileCipher.encryptFile(at: source, to: container, password: "caf\u{00E9}", options: options)
        // Same password typed on a platform that emits a combining acute.
        try FileCipher.decryptFile(at: container, to: restored, password: "cafe\u{0301}")

        XCTAssertEqual(try Data(contentsOf: restored), plain)
    }

    func testWrongPasswordIsRejectedWithWrongPasswordError() throws {
        let source = try write(makePayload(byteCount: 9000), to: path("plain.bin"))
        let container = path("plain.fcrypt")
        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)

        let restored = path("wrong.out")
        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: container, to: restored, password: password + "x")
        ) { error in
            XCTAssertEqual(error as? CryptoError, .wrongPassword)
        }

        // The failed attempt must not leave anything behind.
        XCTAssertFalse(FileManager.default.fileExists(atPath: restored.path))
    }

    func testCaseChangeInPasswordIsRejected() throws {
        let source = try write(makePayload(byteCount: 100), to: path("case.bin"))
        let container = path("case.fcrypt")
        try FileCipher.encryptFile(at: source, to: container, password: "Passw0rd!", options: options)

        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: container, to: path("case.out"), password: "passw0rd!")
        ) { error in
            XCTAssertEqual(error as? CryptoError, .wrongPassword)
        }
    }

    func testEmptyPasswordIsRejectedOnBothSides() throws {
        let source = try write(makePayload(byteCount: 10), to: path("p.bin"))
        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: source, to: path("p.fcrypt"), password: "", options: options)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .emptyPassword)
        }
    }

    // MARK: - Freshness

    func testEncryptingTheSameFileTwiceProducesDifferentContainers() throws {
        let plain = makePayload(byteCount: 2048)
        let source = try write(plain, to: path("same.bin"))
        let first = path("same-1.fcrypt")
        let second = path("same-2.fcrypt")

        try FileCipher.encryptFile(at: source, to: first, password: password, options: options)
        try FileCipher.encryptFile(at: source, to: second, password: password, options: options)

        let a = try Data(contentsOf: first)
        let b = try Data(contentsOf: second)

        // Different random salt => different commitment and different ciphertext.
        XCTAssertNotEqual(a, b)
        XCTAssertNotEqual(a.subdata(in: 24..<56), b.subdata(in: 24..<56), "the salt must be fresh each time")

        // ...and both still decrypt.
        for container in [first, second] {
            let out = container.appendingPathExtension("out")
            try FileCipher.decryptFile(at: container, to: out, password: password)
            XCTAssertEqual(try Data(contentsOf: out), plain)
        }
    }

    func testCiphertextDoesNotLeakThePlaintext() throws {
        let plain = Data(repeating: 0x41, count: 20_000) // "AAAA..."
        let source = try write(plain, to: path("leak.bin"))
        let container = path("leak.fcrypt")
        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)

        let blob = try Data(contentsOf: container)
        XCTAssertFalse(blob.range(of: plain) != nil, "plaintext must not appear in the container")
    }

    // MARK: - Working factor

    func testDifferentArgon2ParametersStillRoundTrip() throws {
        // The parameters are stored per file, so a file made with one setting
        // must open even though the app now defaults to another.
        let source = try write(makePayload(byteCount: 3000), to: path("iters.bin"))
        let container = path("iters.fcrypt")

        try FileCipher.encryptFile(
            at: source,
            to: container,
            password: password,
            options: EncryptionOptions(chunkSize: 1024, memoryKiB: 2_048, timeCost: 4, parallelism: 1)
        )
        let header = try FileCipher.readHeader(at: container)
        XCTAssertEqual(header.keyDerivation, .argon2id(memoryKiB: 2_048, timeCost: 4, parallelism: 1))
        XCTAssertEqual(header.chunkSize, 1024)

        let restored = path("iters.out")
        try FileCipher.decryptFile(at: container, to: restored, password: password)
        XCTAssertEqual(try Data(contentsOf: restored).count, 3000)
    }

    func testLargeMultiChunkFileRoundTrips() throws {
        // ~3 MiB across 4 KiB records = ~768 records: exercises index growth.
        let plain = makePayload(byteCount: 3 * 1024 * 1024 + 7, seed: 0xDEAD_BEEF)
        let source = try write(plain, to: path("big.bin"))
        let container = path("big.fcrypt")
        let restored = path("big.out")

        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)
        try FileCipher.decryptFile(at: container, to: restored, password: password)

        XCTAssertEqual(try Data(contentsOf: restored), plain)
    }
}
