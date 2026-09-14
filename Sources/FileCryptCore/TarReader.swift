//
//  TarReader.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Reads entries from a `tar` byte stream.
///
/// Content must be consumed before the next header is read; `next()` does that
/// automatically for entries the caller ignored, so a caller that only wants
/// the listing cannot desynchronise the stream.
final class TarReader {

    /// Pulls the next chunk of archive bytes, or `nil` at end of input.
    typealias Source = () throws -> Data?

    struct Entry {
        var path: String
        var type: Tar.EntryType
        var size: Int64
        var mode: UInt16
        var modificationTime: Int64
        var linkName: String

        var isDirectory: Bool { type == .directory }
        var isRegularFile: Bool { type == .regular }
        var isSymbolicLink: Bool { type == .symbolicLink }
    }

    private let source: Source
    private var buffer = Data()
    private var reachedEnd = false

    /// Bytes of the current entry's content still to be read.
    private var contentRemaining: Int64 = 0
    /// Block padding that follows the current entry's content.
    private var paddingRemaining: Int = 0
    /// Set once at least one entry has been returned.
    private var hasCurrentEntry = false

    /// Pending PAX overrides applied to the next real entry.
    private var pendingPax: [String: String] = [:]

    init(source: @escaping Source) {
        self.source = source
    }

    // MARK: - Buffered reading

    private func fill(_ minimum: Int) throws {
        while buffer.count < minimum {
            guard let chunk = try source(), !chunk.isEmpty else { return }
            buffer.append(chunk)
        }
    }

    private func readExactly(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        try fill(count)
        guard buffer.count >= count else {
            throw CryptoError.corruptedFile(reason: "the archive ended in the middle of a record.")
        }
        let result = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return result
    }

    private func readBlock() throws -> [UInt8]? {
        try fill(Tar.blockSize)
        if buffer.isEmpty { return nil }
        guard buffer.count >= Tar.blockSize else {
            throw CryptoError.corruptedFile(reason: "the archive ends with a partial block.")
        }
        return [UInt8](try readExactly(Tar.blockSize))
    }

    // MARK: - Iteration

    /// Advance to the next entry, finishing off the previous one first.
    func next() throws -> Entry? {
        if hasCurrentEntry {
            try finishCurrentEntry()
        }
        if reachedEnd { return nil }

        while true {
            guard let block = try readBlock() else { return nil }

            // A zero block begins the end-of-archive marker.
            if block.allSatisfy({ $0 == 0 }) {
                reachedEnd = true
                return nil
            }

            guard let header = try Tar.Header.decode(block) else { return nil }

            switch header.type {
            case .extendedHeader:
                let payload = try readExactly(Int(header.size))
                try consumePadding(for: Int(header.size))
                pendingPax.merge(Tar.parsePaxRecords(payload)) { _, new in new }
                continue

            case .gnuLongName, .gnuLongLink:
                // GNU's convention, written by older tools. Accepted so that an
                // archive produced elsewhere can still be read.
                let payload = try readExactly(Int(header.size))
                try consumePadding(for: Int(header.size))
                let value = String(decoding: payload.prefix { $0 != 0 }, as: UTF8.self)
                pendingPax[header.type == .gnuLongName ? "path" : "linkpath"] = value
                continue

            default:
                break
            }

            var entry = Entry(
                path: header.name,
                type: header.type,
                size: header.size,
                mode: header.mode,
                modificationTime: header.modificationTime,
                linkName: header.linkName
            )

            // Apply any PAX overrides gathered for this entry.
            if let path = pendingPax["path"] { entry.path = path }
            if let link = pendingPax["linkpath"] { entry.linkName = link }
            if let sizeText = pendingPax["size"], let size = Int64(sizeText) { entry.size = size }
            if let modeText = pendingPax["mode"], let mode = Tar.parseOctalString(modeText) {
                entry.mode = UInt16(truncatingIfNeeded: mode)
            }
            if let timeText = pendingPax["mtime"], let time = Int64(timeText) {
                entry.modificationTime = time
            }
            pendingPax.removeAll()

            // Directories carry no content even if a writer stored a length;
            // trusting it would desynchronise the stream.
            if entry.type == .directory { entry.size = 0 }
            if entry.type == .symbolicLink { entry.size = 0 }

            contentRemaining = entry.size
            paddingRemaining = Tar.paddingLength(for: Int(entry.size))
            hasCurrentEntry = true
            return entry
        }
    }

    /// Read up to `count` bytes of the current entry's content.
    func readContent(upTo count: Int) throws -> Data {
        guard contentRemaining > 0 else { return Data() }
        let wanted = Int(min(Int64(count), contentRemaining))
        let data = try readExactly(wanted)
        contentRemaining -= Int64(data.count)
        return data
    }

    /// Discard whatever is left of the current entry, including block padding.
    func skipContent() throws {
        while contentRemaining > 0 {
            let step = Int(min(contentRemaining, 1 << 20))
            _ = try readExactly(step)
            contentRemaining -= Int64(step)
        }
    }

    /// Consume the trailing padding of the current entry so the next header
    /// starts at a block boundary.
    private func finishCurrentEntry() throws {
        try skipContent()
        if paddingRemaining > 0 {
            _ = try readExactly(paddingRemaining)
            paddingRemaining = 0
        }
        hasCurrentEntry = false
    }

    private func consumePadding(for size: Int) throws {
        let padding = Tar.paddingLength(for: size)
        if padding > 0 {
            _ = try readExactly(padding)
        }
    }
}

// MARK: - Extraction

/// Writes a `tar` stream to disk.
///
/// Every path that reaches the filesystem has been through `TarPath`, because
/// an archive is untrusted input. It can only have been produced by someone who
/// knows the password, but "someone who knows the password" is not the same as
/// "someone who means you no harm".
enum TarExtractor {

    struct Result: Equatable {
        var fileCount = 0
        var directoryCount = 0
        var symbolicLinkCount = 0
        var skippedCount = 0
        var totalBytes: Int64 = 0
    }

    /// Extract into `destination`, which must already exist.
    @discardableResult
    static func extract(
        reader: TarReader,
        to destination: URL,
        progress: ((Int64) -> Void)? = nil
    ) throws -> Result {
        var result = Result()
        let root = destination.standardizedFileURL

        /// Archive paths of symlinks created so far. Writing *through* a
        /// symlink is the attack this blocks.
        var createdSymlinks: Set<String> = []

        while let entry = try reader.next() {
            let path = TarPath.normalised(entry.path)

            guard TarPath.isSafeArchivePath(path) else {
                throw CryptoError.corruptedFile(
                    reason: "\"\(entry.path)\" is not a safe path to extract."
                )
            }

            // Refuse to write anywhere beneath a symlink we created.
            if let escape = TarPath.ancestors(of: path).first(where: { createdSymlinks.contains($0) }) {
                throw CryptoError.corruptedFile(
                    reason: "\"\(entry.path)\" would be written through the link \"\(escape)\"."
                )
            }

            let target = path.split(separator: "/").reduce(root) { url, component in
                url.appendingPathComponent(String(component))
            }

            // Belt and braces: the path must stay inside the destination.
            let resolved = target.standardizedFileURL.path
            guard resolved == root.path || resolved.hasPrefix(root.path + "/") else {
                throw CryptoError.corruptedFile(
                    reason: "\"\(entry.path)\" would extract outside the destination folder."
                )
            }

            switch entry.type {
            case .directory:
                try FileManager.default.createDirectory(
                    at: target,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                result.directoryCount += 1

            case .regular:
                try FileManager.default.createDirectory(
                    at: target.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                guard FileManager.default.createFile(atPath: target.path, contents: nil) else {
                    throw CryptoError.ioError("Could not create \"\(entry.path)\" during extraction.")
                }
                let handle: FileHandle
                do {
                    handle = try FileHandle(forWritingTo: target)
                } catch {
                    throw CryptoError.ioError(
                        "Could not open \(entry.path) for writing during extraction: \(error.localizedDescription)"
                    )
                }

                var written: Int64 = 0
                do {
                    while written < entry.size {
                        let step = Int(min(entry.size - written, 1 << 20))
                        let chunk = try reader.readContent(upTo: step)
                        if chunk.isEmpty { break }
                        try handle.write(contentsOf: chunk)
                        written += Int64(chunk.count)
                    }
                    try handle.close()
                } catch {
                    try? handle.close()
                    throw error
                }

                guard written == entry.size else {
                    throw CryptoError.corruptedFile(
                        reason: "\"\(entry.path)\" is shorter than its header declares."
                    )
                }
                result.totalBytes += written
                result.fileCount += 1
                progress?(written)

                let permissions = entry.mode & 0o7777
                if permissions != 0 {
                    try? FileManager.default.setAttributes(
                        [.posixPermissions: NSNumber(value: permissions)],
                        ofItemAtPath: target.path
                    )
                }

            case .symbolicLink:
                try FileManager.default.createDirectory(
                    at: target.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                // Creating the link is safe; the ancestor check above is what
                // stops a later entry from being written through it.
                try? FileManager.default.removeItem(at: target)
                do {
                    try FileManager.default.createSymbolicLink(
                        atPath: target.path,
                        withDestinationPath: entry.linkName
                    )
                } catch {
                    throw CryptoError.ioError(
                        "Could not recreate the link \"\(entry.path)\": \(error.localizedDescription)"
                    )
                }
                createdSymlinks.insert(path)
                result.symbolicLinkCount += 1

            default:
                result.skippedCount += 1
            }
        }

        return result
    }
}
