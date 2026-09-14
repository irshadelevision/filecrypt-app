//
//  FileCipherIntegrityTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Adversarial tests: every structural attack the format is designed to
/// detect must actually be detected, and must leave nothing behind on disk.
final class FileCipherIntegrityTests: TemporaryDirectoryTestCase {

    private let options = EncryptionOptions.testing
    private let password = "integrity-test-password"

    private enum TestFailure: Error {
        case malformedContainer
    }

    /// Split a container into its header and framed records.
    private func parseRecords(_ blob: Data) throws -> (header: Data, records: [Data]) {
        let bytes = [UInt8](blob)
        var offset = TestFormat.headerSize
        var records: [Data] = []

        while offset < bytes.count {
            guard bytes.count - offset >= 4 else { throw TestFailure.malformedContainer }
            let length = Int(ByteCoding.readUInt32LE(bytes, at: offset))
            offset += 4
            guard bytes.count - offset >= length else { throw TestFailure.malformedContainer }
            records.append(Data(bytes[offset..<(offset + length)]))
            offset += length
        }
        return (Data(bytes[0..<TestFormat.headerSize]), records)
    }

    /// Build a container whose records are exactly `recordChunkSize` plaintext
    /// bytes each, except the final one which is 100 bytes.
    private func buildContainer(recordChunkSize: Int, recordCount: Int) throws -> (url: URL, plain: Data) {
        let chunkSize = max(Int(FileHeader.minimumChunkSize), recordChunkSize)
        let plain = makePayload(byteCount: chunkSize * (recordCount - 1) + 100, seed: 7)
        let source = try write(plain, to: path("source.bin"))
        let container = path("source.fcrypt")
        try FileCipher.encryptFile(
            at: source,
            to: container,
            password: password,
            options: EncryptionOptions(chunkSize: chunkSize, memoryKiB: TestFormat.memoryKiB, timeCost: TestFormat.timeCost, parallelism: TestFormat.parallelism)
        )
        return (container, plain)
    }

    private func assertRejected(_ blob: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        let broken = path("broken-\(UUID().uuidString).fcrypt")
        try blob.write(to: broken)
        let output = path("broken-\(UUID().uuidString).out")

        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: broken, to: output, password: password),
            "tampered container was accepted",
            file: file,
            line: line
        )
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: output.path),
            "a failed decryption left a partial file behind",
            file: file,
            line: line
        )
    }

    // MARK: - Truncation

    func testEveryTruncationIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 4096, recordCount: 3)
        let blob = try Data(contentsOf: container)

        // Cut at the header, mid-prefix, mid-body, mid-tag, and by whole records.
        let cutPoints = [
            TestFormat.headerSize - 1,       // header itself short
            TestFormat.headerSize,           // header only, no records
            TestFormat.headerSize + 2,       // half a length prefix
            TestFormat.headerSize + 4 + 100, // mid ciphertext
            TestFormat.headerSize + 4 + 4096 + 8, // mid tag
            TestFormat.headerSize + 4 + 4096 + 16, // exactly one record
            blob.count - 1,
            blob.count - 20
        ]

        for cut in cutPoints where cut > 0 && cut < blob.count {
            try assertRejected(blob.prefix(cut), file: #filePath, line: #line)
        }
    }

    func testContainerWithOnlyHeaderIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 1024, recordCount: 2)
        let blob = try Data(contentsOf: container)
        try assertRejected(blob.prefix(TestFormat.headerSize))
    }

    // MARK: - Extension

    func testAppendedGarbageIsRejected() throws {
        var blob = try Data(contentsOf: buildContainer(recordChunkSize: 1024, recordCount: 2).url)

        // Appending one full, well-formed-looking record.
        blob.append(contentsOf: [0x10, 0x00, 0x00, 0x00])
        blob.append(Data(repeating: 0xAA, count: 16))
        try assertRejected(blob)

        // Appending a single byte.
        var oneByte = try Data(contentsOf: buildContainer(recordChunkSize: 1024, recordCount: 2).url)
        oneByte.append(0x00)
        try assertRejected(oneByte)
    }

    func testDuplicatingTheLastRecordIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 1024, recordCount: 3)
        let blob = try Data(contentsOf: container)
        let parsed = try parseRecords(blob)

        var tampered = parsed.header
        tampered.append(contentsOf: parsed.records[0])
        tampered.append(contentsOf: parsed.records[1])
        tampered.append(contentsOf: parsed.records[2])
        tampered.append(contentsOf: parsed.records[2]) // replay record 2 as record 3
        try assertRejected(tampered)
    }

    // MARK: - Reordering

    func testSwappingTwoRecordsIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 1024, recordCount: 3)
        let parsed = try parseRecords(try Data(contentsOf: container))
        XCTAssertEqual(parsed.records.count, 3)

        func frame(_ record: Data) -> Data {
            var out = Data()
            out.fcAppendUInt32LE(UInt32(record.count))
            out.append(record)
            return out
        }

        var swapped = parsed.header
        for record in [parsed.records[1], parsed.records[0], parsed.records[2]] {
            swapped.append(frame(record))
        }
        try assertRejected(swapped)

        // The same record moved to the end must also fail (index is bound).
        var rotated = parsed.header
        for record in [parsed.records[1], parsed.records[2], parsed.records[0]] {
            rotated.append(frame(record))
        }
        try assertRejected(rotated)
    }

    // MARK: - Bit flips

    func testFlippingAnyCiphertextBitIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 1024, recordCount: 2)
        let blob = try Data(contentsOf: container)

        // First ciphertext byte, a middle byte, and the first tag byte.
        let positions = [
            TestFormat.headerSize + 4,
            TestFormat.headerSize + 4 + 500,
            TestFormat.headerSize + 4 + 1024
        ]
        for position in positions {
            try assertRejected(blob.flippedBit(at: position))
        }
    }

    func testFlippingAHeaderBitIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 256, recordCount: 1)
        let blob = try Data(contentsOf: container)

        // Every byte of the header is authenticated in one way or another:
        // the salt/iterations flow into the key (commitment fails), the rest
        // is covered by the record AAD or rejected during parsing.
        for position in 0..<TestFormat.headerSize {
            let tampered = blob.flippedBit(at: position)
            let broken = path("header-\(position).fcrypt")
            try tampered.write(to: broken)
            let output = path("header-\(position).out")

            XCTAssertThrowsError(
                try FileCipher.decryptFile(at: broken, to: output, password: password),
                "flipping header byte \(position) was not detected"
            )
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        }
    }

    // MARK: - Not our format

    func testRandomFileIsRejectedAsNotEncrypted() throws {
        let random = try write(makePayload(byteCount: 5000, seed: 99), to: path("random.bin"))
        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: random, to: path("random.out"), password: password)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .notEncryptedFile)
        }
    }

    func testFileSmallerThanAHeaderIsRejected() throws {
        let tiny = try write(Data(repeating: 0, count: 10), to: path("tiny.bin"))
        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: tiny, to: path("tiny.out"), password: password)
        )
    }

    func testPlausibleMagicWithCorruptHeaderIsRejected() throws {
        // Correct magic, everything else nonsense.
        var blob = Data(TestFormat.magic)
        blob.append(Data(repeating: 0xFF, count: TestFormat.headerSize - TestFormat.magic.count))
        try assertRejected(blob)
    }

    // MARK: - Header validation

    func testHeaderDecodeRejectsEachFieldIndividually() throws {
        let (container, _) = try buildContainer(recordChunkSize: 256, recordCount: 1)
        let good = [UInt8](try Data(contentsOf: container)).prefix(TestFormat.headerSize).map { $0 }

        func mutate(_ position: Int, _ value: UInt8) throws -> FileHeader {
            var bytes = good
            bytes[position] = value
            return try FileHeader.decode(Data(bytes))
        }

        XCTAssertThrowsError(try mutate(0, 0x00)) { XCTAssertEqual($0 as? CryptoError, .notEncryptedFile) }
        XCTAssertThrowsError(try mutate(8, 3))     // version disagrees with the magic
        XCTAssertThrowsError(try mutate(9, 9))     // unknown kdf
        XCTAssertThrowsError(try mutate(10, 9))    // unknown cipher
        XCTAssertThrowsError(try mutate(11, 0x01)) // unknown flags

        // Header size field (offset 28 in format 2) must agree with the layout.
        var wrongSize = good
        wrongSize[28] = 0x00
        wrongSize[29] = 0x00
        XCTAssertThrowsError(try FileHeader.decode(Data(wrongSize)))

        // Chunk size below/above the allowed band.
        var tooSmall = good
        tooSmall[12] = 0x01; tooSmall[13] = 0x00; tooSmall[14] = 0x00; tooSmall[15] = 0x00
        XCTAssertThrowsError(try FileHeader.decode(Data(tooSmall)))

        var tooLarge = good
        tooLarge[12] = 0xFF; tooLarge[13] = 0xFF; tooLarge[14] = 0xFF; tooLarge[15] = 0x7F
        XCTAssertThrowsError(try FileHeader.decode(Data(tooLarge)))

        // Absurd Argon2 memory cost: must be refused *before* anything is
        // allocated, otherwise a hostile file picks how much RAM we burn.
        var absurdMemory = good
        absurdMemory[16] = 0xFF; absurdMemory[17] = 0xFF; absurdMemory[18] = 0xFF; absurdMemory[19] = 0x7F
        XCTAssertThrowsError(try FileHeader.decode(Data(absurdMemory)))

        // Absurd time cost.
        var absurdTime = good
        absurdTime[20] = 0xFF; absurdTime[21] = 0x00; absurdTime[22] = 0x00; absurdTime[23] = 0x00
        XCTAssertThrowsError(try FileHeader.decode(Data(absurdTime)))

        // Zero lanes.
        var noLanes = good
        noLanes[24] = 0x00; noLanes[25] = 0x00; noLanes[26] = 0x00; noLanes[27] = 0x00
        XCTAssertThrowsError(try FileHeader.decode(Data(noLanes)))
    }

    /// The 8 KiB-per-lane rule is enforced while parsing, not merely while
    /// encrypting: a file that declares an impossible combination is rejected
    /// rather than handed to the C library to fail obscurely.
    func testHeaderRejectsMemoryBelowEightKiBPerLane() throws {
        let (container, _) = try buildContainer(recordChunkSize: 256, recordCount: 1)
        var bytes = [UInt8](try Data(contentsOf: container)).prefix(TestFormat.headerSize).map { $0 }

        // memory = 8 KiB, parallelism = 16  ->  8 < 8 * 16
        bytes[16] = 8; bytes[17] = 0; bytes[18] = 0; bytes[19] = 0
        bytes[24] = 16; bytes[25] = 0; bytes[26] = 0; bytes[27] = 0

        XCTAssertThrowsError(try FileHeader.decode(Data(bytes))) { error in
            guard case CryptoError.corruptedFile = error else {
                return XCTFail("expected .corruptedFile, got \(error)")
            }
        }
    }

    func testHeaderRoundTripsExactly() throws {
        let header = FileHeader(
            chunkSize: 65_536,
            salt: Data(repeating: 0x7F, count: 32),
            commitment: Data(repeating: 0x11, count: 32),
            keyDerivation: .argon2id(memoryKiB: 65_536, timeCost: 3, parallelism: 1)
        )
        let encoded = header.encoded()
        XCTAssertEqual(encoded.count, TestFormat.headerSize)

        let decoded = try FileHeader.decode(encoded)
        XCTAssertEqual(decoded, header)
        XCTAssertEqual(decoded.prefixBytes().count, TestFormat.prefixSize)
        XCTAssertEqual(encoded.prefix(TestFormat.prefixSize), decoded.prefixBytes())
    }

    func testLegacyHeaderRoundTripsExactly() throws {
        let header = FileHeader(
            chunkSize: 65_536,
            salt: Data(repeating: 0x7F, count: 32),
            commitment: Data(repeating: 0x11, count: 32),
            keyDerivation: .pbkdf2SHA512(iterations: 600_000)
        )
        let encoded = header.encoded()
        XCTAssertEqual(encoded.count, 88)
        XCTAssertEqual([UInt8](encoded.prefix(8)), Array("FCRYPTv1".utf8))

        let decoded = try FileHeader.decode(encoded)
        XCTAssertEqual(decoded, header)
        XCTAssertEqual(decoded.format, .pbkdf2SHA512)
        XCTAssertEqual(decoded.prefixBytes().count, 56)
    }

    // MARK: - Paths

    func testSameInputAndOutputIsRejected() throws {
        let source = try write(makePayload(byteCount: 100), to: path("same.bin"))
        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: source, to: source, password: password, options: options)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .inputAndOutputAreSame)
        }
    }

    func testMissingInputIsRejected() {
        let missing = path("does-not-exist.bin")
        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: missing, to: path("out.fcrypt"), password: password, options: options)
        )
    }

    /// A destination that is already a directory must be rejected *before* any
    /// work happens. It used to be caught only by `rename()` at the very end,
    /// after the whole file had been through Argon2id and AES-GCM.
    func testDestinationThatIsADirectoryIsRejectedImmediately() throws {
        let source = try makePayload(byteCount: 4 * 1_024 * 1_024)
        let sourceURL = try write(source, to: path("src.bin"))

        let directory = path("outdir")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let started = CFAbsoluteTimeGetCurrent()
        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: sourceURL, to: directory, password: password, options: options)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .destinationIsDirectory(name: "outdir"))
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - started

        // The check is a stat, not a stream: 4 MiB should not have been hashed.
        XCTAssertLessThan(elapsed, 1.0, "the destination was only validated after doing the work")

        // And nothing was written into the directory.
        let contents = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertTrue(contents.isEmpty, "a temporary file was created for an impossible destination")
    }

    func testDecryptDestinationThatIsADirectoryIsRejected() throws {
        let (container, _) = try buildContainer(recordChunkSize: 4_096, recordCount: 2)
        let directory = path("decrypt-outdir")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        XCTAssertThrowsError(
            try FileCipher.decryptFile(at: container, to: directory, password: password)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .destinationIsDirectory(name: "decrypt-outdir"))
        }
    }

    /// `fileExists` follows symlinks, so a link to a directory is a directory.
    func testDestinationSymlinkedToADirectoryIsRejected() throws {
        let source = try write(makePayload(byteCount: 1_024), to: path("src.bin"))
        let directory = path("real-dir")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let link = path("dir-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)

        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: source, to: link, password: password, options: options)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .destinationIsDirectory(name: "dir-link"))
        }
    }

    /// A dangling symlink is a legitimate destination: the rename replaces the
    /// link itself, which is how every Unix tool behaves.
    func testDanglingSymlinkDestinationIsAllowed() throws {
        let plain = makePayload(byteCount: 2_048)
        let source = try write(plain, to: path("src.bin"))

        let link = path("dangling-link")
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: path("does-not-exist")
        )

        try FileCipher.encryptFile(at: source, to: link, password: password, options: options)

        let restored = path("dangling.out")
        try FileCipher.decryptFile(at: link, to: restored, password: password)
        XCTAssertEqual(try Data(contentsOf: restored), plain)
    }

    func testMissingDestinationFolderIsRejected() throws {
        let source = try write(makePayload(byteCount: 100), to: path("src.bin"))
        let badDestination = path("no-such-folder").appendingPathComponent("out.fcrypt")
        XCTAssertThrowsError(
            try FileCipher.encryptFile(at: source, to: badDestination, password: password, options: options)
        )
    }

    // MARK: - No stray temporary files

    func testNoTemporaryFilesAreLeftBehindOnFailure() throws {
        let (container, _) = try buildContainer(recordChunkSize: 1024, recordCount: 2)
        let blob = try Data(contentsOf: container)

        let broken = path("broken.fcrypt")
        try blob.flippedBit(at: TestFormat.headerSize + 5).write(to: broken)
        _ = try? FileCipher.decryptFile(at: broken, to: path("broken.out"), password: password)

        let leftovers = try FileManager.default
            .contentsOfDirectory(atPath: scratch.path)
            .filter { $0.contains(".part") || $0.hasSuffix(".tmp") }
        XCTAssertTrue(leftovers.isEmpty, "temporary files were left behind: \(leftovers)")
    }

    func testTemporaryPermissionsAreRestoredFromTheSource() throws {
        let source = try write(makePayload(byteCount: 200), to: path("perm.bin"))
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: source.path)

        let container = path("perm.fcrypt")
        try FileCipher.encryptFile(at: source, to: container, password: password, options: options)

        let attributes = try FileManager.default.attributesOfItem(atPath: container.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(permissions, 0o640)
    }

    func testExistingDestinationIsReplacedAtomically() throws {
        let source = try write(makePayload(byteCount: 500), to: path("replace.bin"))
        let destination = try write(Data("i was here first".utf8), to: path("replace.fcrypt"))

        try FileCipher.encryptFile(at: source, to: destination, password: password, options: options)

        // The old contents must be gone and the new file must be decryptable.
        let restored = path("replace.out")
        try FileCipher.decryptFile(at: destination, to: restored, password: password)
        XCTAssertEqual(try Data(contentsOf: restored).count, 500)
    }

    // MARK: - Cancellation

    func testCancellationStopsTheRunAndLeavesNothingBehind() throws {
        let source = try write(makePayload(byteCount: 2 * 1024 * 1024), to: path("cancel.bin"))
        let destination = path("cancel.fcrypt")

        let flag = CancellationFlag()
        flag.cancel() // pre-cancelled

        XCTAssertThrowsError(
            try FileCipher.encryptFile(
                at: source,
                to: destination,
                password: password,
                options: options,
                cancellation: flag
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .cancelled)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))

        let leftovers = try FileManager.default
            .contentsOfDirectory(atPath: scratch.path)
            .filter { $0.contains(".part") }
        XCTAssertTrue(leftovers.isEmpty)
    }

    /// Cancelling from inside the progress callback is deterministic: the very
    /// first callback fires on the first record, so the next loop iteration
    /// must observe the flag and abort.
    func testCancellingMidwayStopsAndCleansUp() throws {
        let source = try write(makePayload(byteCount: 512 * 1024), to: path("mid.bin"))
        let destination = path("mid.fcrypt")

        let flag = CancellationFlag()
        var callbacks = 0

        XCTAssertThrowsError(
            try FileCipher.encryptFile(
                at: source,
                to: destination,
                password: password,
                options: options,
                cancellation: flag,
                progress: { _ in
                    callbacks += 1
                    flag.cancel()
                }
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .cancelled)
        }

        XCTAssertGreaterThan(callbacks, 0, "the progress callback never fired")
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertTrue(
            try FileManager.default.contentsOfDirectory(atPath: scratch.path)
                .filter { $0.contains(".part") }
                .isEmpty,
            "cancelling left a partial file behind"
        )
    }

    func testCancellingADecryptionStopsAndCleansUp() throws {
        let (container, _) = try buildContainer(recordChunkSize: 4096, recordCount: 40)
        let destination = path("mid-decrypt.out")

        let flag = CancellationFlag()
        var callbacks = 0

        XCTAssertThrowsError(
            try FileCipher.decryptFile(
                at: container,
                to: destination,
                password: password,
                cancellation: flag,
                progress: { _ in
                    callbacks += 1
                    flag.cancel()
                }
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .cancelled)
        }

        XCTAssertGreaterThan(callbacks, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    // MARK: - Inspection

    func testLooksEncryptedDistinguishesContainers() throws {
        let plain = try write(makePayload(byteCount: 64), to: path("look.bin"))
        XCTAssertFalse(FileCipher.looksEncrypted(plain))

        let container = path("look.fcrypt")
        try FileCipher.encryptFile(at: plain, to: container, password: password, options: options)
        XCTAssertTrue(FileCipher.looksEncrypted(container))

        let empty = try write(Data(), to: path("look-empty.bin"))
        XCTAssertFalse(FileCipher.looksEncrypted(empty))
    }

    func testReadHeaderReturnsStoredParameters() throws {
        let source = try write(makePayload(byteCount: 100), to: path("read.bin"))
        let container = path("read.fcrypt")
        try FileCipher.encryptFile(
            at: source,
            to: container,
            password: password,
            options: EncryptionOptions(chunkSize: 2048, memoryKiB: 2_048, timeCost: 5, parallelism: 2)
        )

        let header = try FileCipher.readHeader(at: container)
        XCTAssertEqual(header.chunkSize, 2048)
        XCTAssertEqual(header.keyDerivation, .argon2id(memoryKiB: 2_048, timeCost: 5, parallelism: 2))
        XCTAssertEqual(header.salt.count, 32)
        XCTAssertEqual(header.commitment.count, 32)
    }
}
