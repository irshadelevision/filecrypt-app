//
//  DirectoryCipherTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Folder encryption end to end, including the cases that only matter because
/// an archive is untrusted input.
final class DirectoryCipherTests: TemporaryDirectoryTestCase {

    private let options = TestFormat.options(chunkSize: 4_096)
    private let password = "folder password"

    // MARK: - Fixtures

    private func makeProject() throws -> URL {
        let root = path("Project")
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("src/nested"),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("empty"), withIntermediateDirectories: true
        )
        try Data("readme".utf8).write(to: root.appendingPathComponent("README.md"))
        try Data().write(to: root.appendingPathComponent("zero.bin"))
        try Data(repeating: 0x5A, count: 30_000).write(to: root.appendingPathComponent("src/data.bin"))
        try Data("deep".utf8).write(to: root.appendingPathComponent("src/nested/deep.txt"))
        try FileManager.default.createSymbolicLink(
            atPath: root.appendingPathComponent("link").path,
            withDestinationPath: "README.md"
        )
        return root
    }

    /// Compare two trees by content, name and type.
    private func treesMatch(_ a: URL, _ b: URL) throws -> Bool {
        let left = try relativePaths(under: a)
        let right = try relativePaths(under: b)
        guard left == right else { return false }

        for relative in left {
            let one = a.appendingPathComponent(relative)
            let two = b.appendingPathComponent(relative)
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: one.path, isDirectory: &isDirectory)
            if isDirectory.boolValue { continue }

            let oneIsLink = (try? FileManager.default.destinationOfSymbolicLink(atPath: one.path)) != nil
            if oneIsLink {
                let twoTarget = try FileManager.default.destinationOfSymbolicLink(atPath: two.path)
                let oneTarget = try FileManager.default.destinationOfSymbolicLink(atPath: one.path)
                if oneTarget != twoTarget { return false }
                continue
            }
            if try Data(contentsOf: one) != (try Data(contentsOf: two)) { return false }
        }
        return true
    }

    private func relativePaths(under root: URL) throws -> [String] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        ) else { return [] }

        // Compare path *components* rather than slicing the string: a naive
        // `dropFirst(root.path.count + 1)` is off by the parent directory and
        // silently compares the wrong things.
        let rootComponents = root.standardizedFileURL.pathComponents
        var result: [String] = []
        for case let url as URL in enumerator {
            let components = url.standardizedFileURL.pathComponents
            guard components.count > rootComponents.count else { continue }
            result.append(components.dropFirst(rootComponents.count).joined(separator: "/"))
        }
        return result.sorted()
    }

    // MARK: - Round trip

    func testFolderRoundTripsExactly() throws {
        let root = try makeProject()
        let container = path("Project.fcrypt")

        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let restored = path("Restored")
        try FileCipher.decryptDirectory(at: container, to: restored, password: password)

        let restoredPaths = try relativePaths(under: restored)
        XCTAssertEqual(
            restoredPaths,
            try relativePaths(under: root),
            "the restored tree has different contents"
        )
        XCTAssertTrue(try treesMatch(root, restored), "restored file contents differ")
    }

    func testContainerIsMarkedAsHoldingAFolder() throws {
        let root = try makeProject()
        let container = path("Project.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let header = try FileCipher.readHeader(at: container)
        XCTAssertTrue(header.containsDirectoryArchive)
        XCTAssertTrue(FileCipher.containsDirectory(container))
        XCTAssertTrue(FileCipher.looksEncrypted(container))
    }

    /// The general entry points must route on what they find, without the
    /// caller having to say which they mean.
    func testEncryptAndDecryptRouteOnTheInput() throws {
        let root = try makeProject()
        let container = path("routed.fcrypt")

        try FileCipher.encrypt(at: root, to: container, password: password, options: options)
        XCTAssertTrue(FileCipher.containsDirectory(container))

        let restored = path("Routed")
        try FileCipher.decrypt(at: container, to: restored, password: password)
        XCTAssertTrue(try treesMatch(root, restored))

        // And a plain file still goes down the file path.
        let file = try write(Data("plain".utf8), to: path("plain.txt"))
        let fileContainer = path("plain.txt.fcrypt")
        try FileCipher.encrypt(at: file, to: fileContainer, password: password, options: options)
        XCTAssertFalse(FileCipher.containsDirectory(fileContainer))
    }

    func testAnEmptyFolderRoundTrips() throws {
        let root = path("Empty")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let container = path("Empty.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let restored = path("EmptyRestored")
        try FileCipher.decryptDirectory(at: container, to: restored, password: password)

        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: restored.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
        XCTAssertEqual(try relativePaths(under: restored), [])
    }

    func testPermissionsSurviveTheRoundTrip() throws {
        let root = path("Modes")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let script = root.appendingPathComponent("run.sh")
        try Data("#!/bin/sh\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)

        let container = path("Modes.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)
        let restored = path("ModesRestored")
        try FileCipher.decryptDirectory(at: container, to: restored, password: password)

        let attributes = try FileManager.default.attributesOfItem(
            atPath: restored.appendingPathComponent("run.sh").path
        )
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    // MARK: - Authentication

    func testWrongPasswordLeavesNothingBehind() throws {
        let root = try makeProject()
        let container = path("Project.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let restored = path("WrongPassword")
        XCTAssertThrowsError(
            try FileCipher.decryptDirectory(at: container, to: restored, password: "nope")
        ) { error in
            XCTAssertEqual(error as? CryptoError, .wrongPassword)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: restored.path))
    }

    /// A tampered container must not leave a half-populated folder. This is what
    /// the staging directory is for.
    func testTamperedFolderArchiveLeavesNoPartialFolder() throws {
        let root = try makeProject()
        let container = path("Project.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        var bytes = try Data(contentsOf: container)
        bytes[bytes.count - 20] ^= 0x01
        let tampered = path("Tampered.fcrypt")
        try bytes.write(to: tampered)

        let restored = path("TamperedOut")
        XCTAssertThrowsError(
            try FileCipher.decryptDirectory(at: tampered, to: restored, password: password)
        )
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: restored.path),
            "a failed restore left a partial folder behind"
        )
        // And no staging directory survived either.
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: scratch.path)
            .filter { $0.contains(".partial") }
        XCTAssertTrue(leftovers.isEmpty, "staging directories left behind: \(leftovers)")
    }

    /// Truncating the container must be detected, not silently produce a
    /// partial folder.
    func testTruncatedFolderArchiveIsRejected() throws {
        let root = try makeProject()
        let container = path("Project.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let bytes = try Data(contentsOf: container)
        let truncated = path("Truncated.fcrypt")
        try bytes.prefix(bytes.count / 2).write(to: truncated)

        let restored = path("TruncatedOut")
        XCTAssertThrowsError(
            try FileCipher.decryptDirectory(at: truncated, to: restored, password: password)
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: restored.path))
    }

    func testAFileContainerCannotBeRestoredAsAFolder() throws {
        let file = try write(Data("just a file".utf8), to: path("single.txt"))
        let container = path("single.txt.fcrypt")
        try FileCipher.encryptFile(at: file, to: container, password: password, options: options)

        // `decryptDirectory` must refuse a container that holds a file, rather
        // than trying to unpack bytes that are not an archive.
        XCTAssertThrowsError(
            try FileCipher.decryptDirectory(
                at: container, to: path("NotAFolder"), password: password
            )
        )
    }

    // MARK: - Scale

    func testAFolderLargerThanTheChunkSizeRoundTrips() throws {
        let root = path("Big")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // Several chunks of content across several files.
        for index in 0..<5 {
            let payload = Data(repeating: UInt8(index), count: 10_000)
            try payload.write(to: root.appendingPathComponent("file\(index).bin"))
        }

        let container = path("Big.fcrypt")
        try FileCipher.encryptDirectory(at: root, to: container, password: password, options: options)

        let restored = path("BigRestored")
        try FileCipher.decryptDirectory(at: container, to: restored, password: password)
        XCTAssertTrue(try treesMatch(root, restored))
    }

    func testProgressIsReportedAndReachesCompletion() throws {
        let root = try makeProject()
        let container = path("Progress.fcrypt")

        var values: [Double] = []
        try FileCipher.encryptDirectory(
            at: root, to: container, password: password, options: options, progress: { values.append($0) }
        )
        XCTAssertFalse(values.isEmpty)
        XCTAssertEqual(values.last, 1.0)
        XCTAssertTrue(values.allSatisfy { $0 >= 0 && $0 <= 1 })
    }
}
