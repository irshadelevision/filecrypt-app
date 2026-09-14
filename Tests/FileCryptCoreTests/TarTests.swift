//
//  TarTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Exercises the archive layer on its own, before any encryption is involved.
///
/// The strongest checks here hand the bytes to the system `tar` and read back
/// what *it* produced, so the format is verified against an independent
/// implementation rather than only against itself.
final class TarTests: TemporaryDirectoryTestCase {

    // MARK: - Helpers

    /// Collect a writer's output into memory.
    private func archive(_ build: (TarWriter) throws -> Void, root: URL) throws -> Data {
        var collected = Data()
        let writer = TarWriter(root: root) { chunk in collected.append(chunk) }
        try build(writer)
        return collected
    }

    private func makeTree() throws -> URL {
        let root = path("tree")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("nested/deeper"),
            withIntermediateDirectories: true
        )
        try Data("hello".utf8).write(to: root.appendingPathComponent("a.txt"))
        try Data().write(to: root.appendingPathComponent("empty.txt"))
        try Data(repeating: 0xAB, count: 5_000).write(to: root.appendingPathComponent("nested/b.bin"))
        try Data("deep".utf8).write(to: root.appendingPathComponent("nested/deeper/c.txt"))
        try FileManager.default.createSymbolicLink(
            atPath: root.appendingPathComponent("link").path,
            withDestinationPath: "a.txt"
        )
        return root
    }

    private func extract(_ data: Data, to destination: URL) throws -> TarExtractor.Result {
        var offset = 0
        let reader = TarReader { () -> Data? in
            guard offset < data.count else { return nil }
            let end = min(offset + 64 * 1024, data.count)
            defer { offset = end }
            return data.subdata(in: offset..<end)
        }
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        return try TarExtractor.extract(reader: reader, to: destination)
    }

    // MARK: - Round trip

    func testRoundTripPreservesTheTree() throws {
        let root = try makeTree()
        let data = try archive({ try $0.write(archiveRootName: "tree") }, root: root)

        let out = path("out")
        let result = try extract(data, to: out)

        XCTAssertEqual(result.fileCount, 4)
        XCTAssertEqual(result.symbolicLinkCount, 1)
        XCTAssertGreaterThanOrEqual(result.directoryCount, 3)

        let restored = out.appendingPathComponent("tree")
        XCTAssertEqual(try Data(contentsOf: restored.appendingPathComponent("a.txt")), Data("hello".utf8))
        XCTAssertEqual(try Data(contentsOf: restored.appendingPathComponent("empty.txt")), Data())
        XCTAssertEqual(
            try Data(contentsOf: restored.appendingPathComponent("nested/b.bin")),
            Data(repeating: 0xAB, count: 5_000)
        )
        XCTAssertEqual(
            try Data(contentsOf: restored.appendingPathComponent("nested/deeper/c.txt")),
            Data("deep".utf8)
        )
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(
                atPath: restored.appendingPathComponent("link").path
            ),
            "a.txt"
        )
    }

    func testEmptyDirectorySurvives() throws {
        let root = path("empties")
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("nothing-here"),
            withIntermediateDirectories: true
        )

        let data = try archive({ try $0.write(archiveRootName: "empties") }, root: root)
        let out = path("out-empty")
        _ = try extract(data, to: out)

        var isDirectory: ObjCBool = false
        let restored = out.appendingPathComponent("empties/nothing-here")
        XCTAssertTrue(FileManager.default.fileExists(atPath: restored.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
    }

    func testHiddenFilesAreIncluded() throws {
        let root = path("hidden")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("secret".utf8).write(to: root.appendingPathComponent(".dotfile"))

        let data = try archive({ try $0.write(archiveRootName: "hidden") }, root: root)
        let out = path("out-hidden")
        _ = try extract(data, to: out)

        XCTAssertEqual(
            try Data(contentsOf: out.appendingPathComponent("hidden/.dotfile")),
            Data("secret".utf8)
        )
    }

    func testExecutableBitIsPreserved() throws {
        let root = path("modes")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let script = root.appendingPathComponent("run.sh")
        try Data("#!/bin/sh\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)

        let data = try archive({ try $0.write(archiveRootName: "modes") }, root: root)
        let out = path("out-modes")
        _ = try extract(data, to: out)

        let attributes = try FileManager.default.attributesOfItem(
            atPath: out.appendingPathComponent("modes/run.sh").path
        )
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o755)
    }

    /// The archive must be byte-identical for the same tree, or the encryption
    /// step stops being reproducible.
    func testArchivesAreDeterministic() throws {
        let root = try makeTree()
        let first = try archive({ try $0.write(archiveRootName: "tree") }, root: root)
        let second = try archive({ try $0.write(archiveRootName: "tree") }, root: root)
        XCTAssertEqual(first, second)
    }

    func testArchiveIsBlockAligned() throws {
        let root = try makeTree()
        let data = try archive({ try $0.write(archiveRootName: "tree") }, root: root)
        XCTAssertEqual(data.count % Tar.blockSize, 0)
    }

    // MARK: - Interoperability with the system tar

    func testSystemTarCanReadOurArchive() throws {
        let root = try makeTree()
        let data = try archive({ try $0.write(archiveRootName: "tree") }, root: root)
        let file = path("ours.tar")
        try data.write(to: file)

        let list = try runTar(["-tf", file.path])
        let names = list.split(separator: "\n").map(String.init)
        XCTAssertTrue(names.contains("tree/a.txt"), "bsdtar listed: \(names)")
        XCTAssertTrue(names.contains("tree/nested/b.bin"))
        XCTAssertTrue(names.contains("tree/link"))

        // And it must actually be able to extract it.
        let destination = path("bsdtar-out")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        _ = try runTar(["-xf", file.path, "-C", destination.path])

        XCTAssertEqual(
            try Data(contentsOf: destination.appendingPathComponent("tree/a.txt")),
            Data("hello".utf8)
        )
        XCTAssertEqual(
            try Data(contentsOf: destination.appendingPathComponent("tree/nested/deeper/c.txt")),
            Data("deep".utf8)
        )
    }

    func testWeCanReadAnArchiveProducedBySystemTar() throws {
        let root = try makeTree()

        // bsdtar writes the GNU/PAX flavour; our reader must cope with it.
        let file = path("theirs.tar")
        _ = try runTar([
            "-cf", file.path,
            "--no-mac-metadata",
            "-C", root.deletingLastPathComponent().path,
            root.lastPathComponent
        ])

        let data = try Data(contentsOf: file)
        let out = path("our-out")
        let result = try extract(data, to: out)

        XCTAssertEqual(result.fileCount, 4)
        XCTAssertEqual(
            try Data(contentsOf: out.appendingPathComponent("tree/nested/b.bin")),
            Data(repeating: 0xAB, count: 5_000)
        )
    }

    /// A path longer than the 100-byte `ustar` name field needs a PAX record.
    func testLongPathsSurvive() throws {
        let root = path("long")
        let deep = root.appendingPathComponent(
            String(repeating: "d", count: 80) + "/" + String(repeating: "e", count: 80)
        )
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        let name = String(repeating: "f", count: 120) + ".txt"
        try Data("long".utf8).write(to: deep.appendingPathComponent(name))

        let data = try archive({ try $0.write(archiveRootName: "long") }, root: root)

        // The system tar must agree it is well formed.
        let file = path("long.tar")
        try data.write(to: file)
        let listed = try runTar(["-tf", file.path])
        XCTAssertTrue(
            listed.contains(name),
            "bsdtar could not read the long path back:\n\(listed)"
        )

        let out = path("out-long")
        _ = try extract(data, to: out)
        XCTAssertEqual(
            try Data(contentsOf: out.appendingPathComponent("long").appendingPathComponent(
                String(repeating: "d", count: 80) + "/" + String(repeating: "e", count: 80) + "/" + name
            )),
            Data("long".utf8)
        )
    }

    // MARK: - Path safety

    func testTraversalPathsAreRejected() {
        XCTAssertFalse(TarPath.isSafeArchivePath("../etc/passwd"))
        XCTAssertFalse(TarPath.isSafeArchivePath("a/../../b"))
        XCTAssertFalse(TarPath.isSafeArchivePath("/etc/passwd"))
        XCTAssertFalse(TarPath.isSafeArchivePath(""))
        XCTAssertFalse(TarPath.isSafeArchivePath("a//b"))
        XCTAssertFalse(TarPath.isSafeArchivePath("."))
        XCTAssertFalse(TarPath.isSafeArchivePath("./a"))
        XCTAssertFalse(TarPath.isSafeArchivePath("a/./b"))
        XCTAssertFalse(TarPath.isSafeArchivePath("a/\0b"))

        XCTAssertTrue(TarPath.isSafeArchivePath("a"))
        XCTAssertTrue(TarPath.isSafeArchivePath("a/b/c.txt"))
        XCTAssertTrue(TarPath.isSafeArchivePath("a/b/"))
        XCTAssertTrue(TarPath.isSafeArchivePath("with space/x-y_z.1"))
    }

    /// A hand-built archive that tries to escape must be refused, and must not
    /// write anything outside the destination.
    func testMaliciousArchiveCannotEscapeViaDotDot() throws {
        let root = try makeTree()
        let honest = try archive({ try $0.write(archiveRootName: "tree") }, root: root)

        // Rewrite the first header's name to a traversal path and fix the
        // checksum, so the archive is structurally valid but hostile.
        var bytes = [UInt8](honest)
        let evil = "../escaped.txt"
        for (index, field) in Tar.Field.name.enumerated() { bytes[field] = 0 }
        for (index, byte) in Array(evil.utf8).enumerated() { bytes[Tar.Field.name.lowerBound + index] = byte }
        recomputeChecksum(&bytes, at: 0)

        let out = path("escape-target")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        XCTAssertThrowsError(try extract(Data(bytes), to: out)) { error in
            guard case CryptoError.corruptedFile = error else {
                return XCTFail("expected .corruptedFile, got \(error)")
            }
        }

        // Nothing may appear beside the destination.
        XCTAssertFalse(FileManager.default.fileExists(atPath: scratch.appendingPathComponent("escaped.txt").path))
    }

    /// The symlink attack: create a link pointing outside, then write through
    /// it. The second entry must be refused.
    func testWritingThroughACreatedSymlinkIsRejected() throws {
        var bytes: [UInt8] = []

        func appendEntry(name: String, type: Tar.EntryType, size: Int, content: Data, link: String = "") throws {
            var header = Tar.Header(
                name: name,
                mode: type == .directory ? 0o755 : 0o644,
                uid: 0, gid: 0,
                size: Int64(size),
                modificationTime: 0,
                type: type,
                linkName: link
            )
            if type == .directory, !header.name.hasSuffix("/") { header.name += "/" }
            bytes.append(contentsOf: try header.encoded())
            if size > 0 {
                bytes.append(contentsOf: [UInt8](content))
                let padding = Tar.paddingLength(for: size)
                if padding > 0 { bytes.append(contentsOf: [UInt8](repeating: 0, count: padding)) }
            }
        }

        try appendEntry(name: "root/", type: .directory, size: 0, content: Data())
        try appendEntry(name: "root/escape", type: .symbolicLink, size: 0, content: Data(), link: "/tmp")
        try appendEntry(name: "root/escape/pwned.txt", type: .regular, size: 5, content: Data("owned".utf8))
        bytes.append(contentsOf: [UInt8](repeating: 0, count: Tar.blockSize * 2))

        let out = path("symlink-target")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

        XCTAssertThrowsError(try extract(Data(bytes), to: out)) { error in
            guard case CryptoError.corruptedFile = error else {
                return XCTFail("expected .corruptedFile, got \(error)")
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/tmp/pwned.txt"))
    }

    // MARK: - Corruption

    func testTruncatedArchiveIsRejected() throws {
        let root = try makeTree()
        let data = try archive({ try $0.write(archiveRootName: "tree") }, root: root)

        let out = path("out-truncated")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        // Cut one block into the archive, which lands inside a header or
        // content rather than on a clean entry boundary.
        let cut = data.count - Tar.blockSize - 100
        XCTAssertThrowsError(try extract(data.prefix(cut), to: out))
    }

    func testCorruptedHeaderChecksumIsRejected() throws {
        let root = try makeTree()
        var bytes = [UInt8](try archive({ try $0.write(archiveRootName: "tree") }, root: root))
        // Flip a byte in the name without fixing the checksum.
        bytes[Tar.Field.name.lowerBound] ^= 0x01

        let out = path("out-badsum")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        XCTAssertThrowsError(try extract(Data(bytes), to: out)) { error in
            guard case CryptoError.corruptedFile = error else {
                return XCTFail("expected .corruptedFile, got \(error)")
            }
        }
    }

    // MARK: - Survey

    func testSurveyCountsMatchWhatIsWritten() throws {
        let root = try makeTree()
        let survey = try TarWriter.survey(root: root)
        let data = try archive({ try $0.write(archiveRootName: "tree") }, root: root)

        XCTAssertEqual(survey.summary.fileCount, 4)
        XCTAssertEqual(survey.summary.symbolicLinkCount, 1)
        XCTAssertGreaterThanOrEqual(survey.summary.directoryCount, 3)
        // The estimate must not under-count, or progress would exceed 100%.
        XCTAssertGreaterThanOrEqual(survey.totalBytes, Int64(data.count))
    }

    // MARK: - Utilities

    private func recomputeChecksum(_ bytes: inout [UInt8], at offset: Int) {
        for index in Tar.Field.checksum { bytes[offset + index] = 0x20 }
        let sum = bytes[offset..<(offset + Tar.blockSize)].reduce(0) { $0 + Int($1) }
        let digits = String(sum, radix: 8)
        let padded = String(repeating: "0", count: max(0, 6 - digits.count)) + digits
        for (index, byte) in Array(padded.utf8).enumerated() where index < 6 {
            bytes[offset + Tar.Field.checksum.lowerBound + index] = byte
        }
        bytes[offset + Tar.Field.checksum.lowerBound + 6] = 0
        bytes[offset + Tar.Field.checksum.lowerBound + 7] = 0x20
    }

    private func runTar(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = arguments
        // macOS bsdtar otherwise stores extended attributes as AppleDouble
        // "._name" companions, which would make the entry counts here describe
        // bsdtar's metadata rather than the tree under test.
        var environment = ProcessInfo.processInfo.environment
        environment["COPYFILE_DISABLE"] = "1"
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "tar", code: Int(process.terminationStatus))
        }
        return String(decoding: output, as: UTF8.self)
    }
}
