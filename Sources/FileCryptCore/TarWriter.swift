//
//  TarWriter.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Turns a directory tree into a `tar` byte stream.
///
/// The tree is walked lazily so that archiving a large folder does not hold it
/// in memory: the caller pulls bytes and the writer reads files as it goes.
public final class TarWriter {

    /// Bytes are handed to this as they are produced.
    public typealias Sink = (Data) throws -> Void

    public struct Summary: Equatable {
        public var fileCount = 0
        public var directoryCount = 0
        public var symbolicLinkCount = 0
        /// Sockets, FIFOs and device nodes. `tar` can represent these but we do
        /// not, and silently dropping them would be a surprise, so they are
        /// counted and reported.
        public var skippedSpecialCount = 0

        public init() {}
    }

    private let root: URL
    private let sink: Sink
    private(set) var summary = Summary()

    public init(root: URL, sink: @escaping Sink) {
        self.root = root
        self.sink = sink
    }

    /// Walk `root` and emit a complete archive.
    ///
    /// - Parameter archiveRootName: the directory name stored as the archive's
    ///   top-level entry. Extracting recreates exactly this folder, which keeps
    ///   the round trip lossless: encrypting `~/Photos` and decrypting it gives
    ///   back a `Photos` folder rather than a bare pile of files.
    public func write(archiveRootName: String) throws {
        var pendingPAX: [String: String] = [:]

        try emitEntry(
            path: archiveRootName,
            type: .directory,
            mode: 0o755,
            size: 0,
            modificationTime: modificationTime(of: root),
            linkName: "",
            pax: [:]
        )
        summary.directoryCount += 1

        try walk(directory: root, archivePath: archiveRootName, pendingPAX: &pendingPAX)
        try emitEndOfArchive()
    }

    // MARK: - Walking

    private func walk(directory: URL, archivePath: String, pendingPAX: inout [String: String]) throws {
        // Sorted so that two runs over the same tree produce identical archives.
        // That makes the encrypt step reproducible and the tests deterministic.
        let contents = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
            options: []   // do NOT skip hidden files: they are part of the folder
        )
        .sorted { $0.lastPathComponent < $1.lastPathComponent }

        for item in contents {
            let name = item.lastPathComponent
            let childPath = archivePath + "/" + name

            let values = try item.resourceValues(forKeys: [
                .isDirectoryKey, .isSymbolicLinkKey, .isRegularFileKey,
                .fileSizeKey, .contentModificationDateKey
            ])

            // `isDirectory` follows symlinks, so a symlink to a directory would
            // look like a directory and be recursed into. Check the link flag
            // first: a symlink is stored as a symlink and never followed, which
            // is both what `tar` does and what stops a link loop from becoming
            // an infinite walk.
            if values.isSymbolicLink == true {
                let target = try FileManager.default.destinationOfSymbolicLink(atPath: item.path)
                try emitEntry(
                    path: childPath,
                    type: .symbolicLink,
                    mode: 0o777,
                    size: 0,
                    modificationTime: modificationTime(of: item),
                    linkName: target,
                    pax: [:]
                )
                summary.symbolicLinkCount += 1
                continue
            }

            if values.isDirectory == true {
                try emitEntry(
                    path: childPath,
                    type: .directory,
                    mode: mode(of: item) ?? 0o755,
                    size: 0,
                    modificationTime: modificationTime(of: item),
                    linkName: "",
                    pax: [:]
                )
                summary.directoryCount += 1
                try walk(directory: item, archivePath: childPath, pendingPAX: &pendingPAX)
                continue
            }

            guard values.isRegularFile == true else {
                summary.skippedSpecialCount += 1
                continue
            }

            let size = Int64(values.fileSize ?? 0)
            try emitEntry(
                path: childPath,
                type: .regular,
                mode: mode(of: item) ?? 0o644,
                size: size,
                modificationTime: modificationTime(of: item),
                linkName: "",
                pax: [:]
            )
            try emitFileContents(item, expectedSize: size)
            summary.fileCount += 1
        }
    }

    // MARK: - Entry emission

    private func emitEntry(
        path: String,
        type: Tar.EntryType,
        mode: UInt16,
        size: Int64,
        modificationTime: Int64,
        linkName: String,
        pax: [String: String]
    ) throws {
        var extra = pax
        var headerName = path
        var headerLink = linkName

        // Decide whether `ustar` can express this path directly, or whether a
        // PAX record is needed. The check has to be exact: a path that does not
        // round-trip through prefix+name would be silently corrupted.
        let (prefix, base) = Tar.splitPath(path)
        let pathFitsInHeader = base.utf8.count <= Tar.nameFieldCapacity
            && prefix.utf8.count <= Tar.prefixFieldCapacity
            && (prefix.isEmpty || prefix.utf8.count + 1 + base.utf8.count == path.utf8.count)

        if !pathFitsInHeader {
            extra["path"] = path
            headerName = String(base.prefix(Tar.nameFieldCapacity))
            if headerName.isEmpty { headerName = "entry" }
        }
        if !linkName.isEmpty, linkName.utf8.count > Tar.linkNameFieldCapacity {
            extra["linkpath"] = linkName
            headerLink = String(linkName.prefix(Tar.linkNameFieldCapacity))
        }
        if size > Tar.maximumOctalValue {
            extra["size"] = String(size)
        }

        if !extra.isEmpty {
            try emitExtendedHeader(extra)
        }

        // A directory conventionally carries a trailing slash.
        if type == .directory, !headerName.hasSuffix("/") {
            headerName += "/"
        }

        var header = Tar.Header(
            name: headerName,
            mode: mode,
            uid: 0,
            gid: 0,
            size: size > Tar.maximumOctalValue ? 0 : size,
            modificationTime: min(max(modificationTime, 0), Tar.maximumOctalValue),
            type: type,
            linkName: headerLink
        )
        header.uid = 0
        header.gid = 0

        try sink(Data(try header.encoded()))
    }

    private func emitExtendedHeader(_ records: [String: String]) throws {
        var payload = Data()
        // Deterministic order, so identical trees give identical archives.
        for key in records.keys.sorted() {
            payload.append(Tar.paxRecord(key: key, value: records[key]!))
        }

        // The declared size is the length of the records themselves. The zero
        // padding that follows to reach a block boundary is implicit.
        //
        // Getting this wrong is not a formatting nicety: declaring the padded
        // length makes libarchive read the trailing NULs as further records and
        // reject the whole header as malformed, which silently discards the
        // long path it was there to carry.
        var header = Tar.Header(
            name: "PaxHeaders/entry",
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: Int64(payload.count),
            modificationTime: 0,
            type: .extendedHeader,
            linkName: ""
        )
        header.name = "PaxHeaders/entry"

        try sink(Data(try header.encoded()))

        var block = [UInt8](payload)
        let padding = Tar.paddingLength(for: payload.count)
        if padding > 0 {
            block.append(contentsOf: [UInt8](repeating: 0, count: padding))
        }
        try sink(Data(block))
    }

    private func emitFileContents(_ url: URL, expectedSize: Int64) throws {
        guard let handle = FileHandle(forReadingAtPath: url.path) else {
            throw CryptoError.ioError("Could not read \"\(url.lastPathComponent)\" while archiving.")
        }
        defer { try? handle.close() }

        var written: Int64 = 0
        let bufferSize = 1 << 20

        while written < expectedSize {
            let remaining = Int(min(Int64(bufferSize), expectedSize - written))
            let chunk: Data?
            do {
                chunk = try handle.read(upToCount: remaining)
            } catch {
                throw CryptoError.ioError("Could not read \"\(url.lastPathComponent)\": \(error.localizedDescription)")
            }
            guard let chunk, !chunk.isEmpty else { break }
            try sink(chunk)
            written += Int64(chunk.count)
        }

        // Pad the file out to a block boundary.
        let remainder = written % Int64(Tar.blockSize)
        if remainder != 0 {
            let padding = Int(Int64(Tar.blockSize) - remainder)
            try sink(Data(repeating: 0, count: padding))
            written += Int64(padding)
        }
    }

    private func emitEndOfArchive() throws {
        try sink(Data(repeating: 0, count: Tar.blockSize * Tar.endOfArchiveBlocks))
    }

    // MARK: - Metadata

    private func modificationTime(of url: URL) -> Int64 {
        guard let date = try? url.resourceValues(forKeys: [.contentModificationDateKey])
            .contentModificationDate else { return 0 }
        return Int64(date.timeIntervalSince1970)
    }

    private func mode(of url: URL) -> UInt16? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let permissions = attributes[.posixPermissions] as? NSNumber else { return nil }
        return UInt16(truncatingIfNeeded: permissions.intValue)
    }

    // MARK: - Sizing

    /// Total bytes the archive will contain, and what is in the tree.
    ///
    /// Used to report progress and to warn about skipped special files before
    /// anything is written.
    public static func survey(root: URL) throws -> (totalBytes: Int64, summary: Summary) {
        var summary = Summary()
        var total: Int64 = 0

        // The root directory entry itself, plus its end-of-archive blocks.
        total += Int64(Tar.blockSize) * Int64(1 + Tar.endOfArchiveBlocks)
        summary.directoryCount += 1

        func visit(_ directory: URL) throws {
            let contents = try FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey],
                options: []
            ).sorted { $0.lastPathComponent < $1.lastPathComponent }

            for item in contents {
                let values = try item.resourceValues(forKeys: [
                    .isDirectoryKey, .isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey
                ])

                let name = item.lastPathComponent
                let nameBlocks = Int64(archiveNameBlocks(for: name))

                if values.isSymbolicLink == true {
                    summary.symbolicLinkCount += 1
                    total += Int64(Tar.blockSize) * nameBlocks
                    continue
                }
                if values.isDirectory == true {
                    summary.directoryCount += 1
                    total += Int64(Tar.blockSize) * nameBlocks
                    try visit(item)
                    continue
                }
                guard values.isRegularFile == true else {
                    summary.skippedSpecialCount += 1
                    continue
                }
                summary.fileCount += 1
                let size = Int64(values.fileSize ?? 0)
                let contentBlocks = (size + Int64(Tar.blockSize) - 1) / Int64(Tar.blockSize)
                // A regular file entry never needs a PAX header for its size
                // unless it exceeds the octal field, which is astronomically
                // unlikely and simply adds one block if it happens.
                let paxBlocks: Int64 = size > Tar.maximumOctalValue ? 2 : 0
                total += Int64(Tar.blockSize) * (nameBlocks + contentBlocks + paxBlocks)
            }
        }

        try visit(root)
        return (total, summary)
    }

    private static func archiveNameBlocks(for name: String) -> Int {
        // Entry cannot be emitted without knowing the full path, so the caller
        // only needs a lower bound here. One block, plus two if a PAX record
        // will be required for the path.
        name.utf8.count > Tar.nameFieldCapacity ? 3 : 1
    }
}
