//
//  Tar.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// The `ustar` archive primitives used to turn a directory into a byte stream.
///
/// Tar is chosen over a bespoke format for one reason: it is boring. It is
/// specified in POSIX, it is readable by every system tool, and the failure
/// modes of a container format are exactly where a hand-rolled design gets
/// things subtly wrong. FileCrypt writes the plain POSIX variant and uses PAX
/// extended headers only where `ustar` cannot express a value.
enum Tar {

    /// Every tar structure is a multiple of this. The number is historical and
    /// entirely arbitrary; it just has to be consistent.
    static let blockSize = 512

    /// Two zero blocks mark the end of an archive.
    static let endOfArchiveBlocks = 2

    enum EntryType: UInt8 {
        case regular = 0x30          // '0'
        case symbolicLink = 0x32     // '2'
        case directory = 0x35        // '5'
        /// PAX extended header: applies to the entry that follows it.
        case extendedHeader = 0x78   // 'x'

        /// GNU tar's long-name convention. Understood when reading, never
        /// written — PAX is the portable way to express the same thing.
        case gnuLongName = 0x4C      // 'L'
        case gnuLongLink = 0x4B      // 'K'
    }

    // MARK: - Header layout

    enum Field {
        static let name = 0 ..< 100
        static let mode = 100 ..< 108
        static let uid = 108 ..< 116
        static let gid = 116 ..< 124
        static let size = 124 ..< 136
        static let modificationTime = 136 ..< 148
        static let checksum = 148 ..< 156
        static let typeFlag = 156 ..< 157
        static let linkName = 157 ..< 257
        static let magic = 257 ..< 263
        static let version = 263 ..< 265
        static let userName = 265 ..< 297
        static let groupName = 297 ..< 329
        static let deviceMajor = 329 ..< 337
        static let deviceMinor = 337 ..< 345
        static let prefix = 345 ..< 500
    }

    /// `"ustar\0"` followed by `"00"` is the POSIX flavour. GNU tar writes
    /// `"ustar "` with a space and an empty version, so both are accepted when
    /// reading.
    static let posixMagic: [UInt8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x00]
    static let gnuMagic: [UInt8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20]

    /// Largest value an 11-digit octal field can hold: 8 GiB - 1.
    static let maximumOctalValue: Int64 = 0o77777777777

    /// A `ustar` name field holds 100 bytes; a longer path needs the 155-byte
    /// prefix field or a PAX record.
    static let nameFieldCapacity = 100
    static let linkNameFieldCapacity = 100
    static let prefixFieldCapacity = 155

    // MARK: - Field encoding

    /// Write a number as octal in a fixed-width field, terminated by NUL.
    ///
    /// Returns `nil` when the value does not fit, so the caller can fall back to
    /// a PAX record rather than writing a truncated — and therefore corrupt —
    /// header.
    static func encodeOctal(_ value: Int64, width: Int) -> [UInt8]? {
        guard value >= 0 else { return nil }
        let digits = String(value, radix: 8)
        // One byte is reserved for the terminator.
        guard digits.count <= width - 1 else { return nil }
        var bytes = [UInt8](repeating: 0x30, count: width - 1)  // '0' padding
        let digitBytes = Array(digits.utf8)
        bytes.replaceSubrange((width - 1 - digitBytes.count)..<(width - 1), with: digitBytes)
        bytes.append(0)
        return bytes
    }

    /// Read a NUL- or space-terminated octal field.
    static func decodeOctal(_ bytes: ArraySlice<UInt8>) -> Int64? {
        var value: Int64 = 0
        var sawDigit = false
        for byte in bytes {
            if byte == 0 || byte == 0x20 {
                if sawDigit { break } else { continue }
            }
            guard byte >= 0x30, byte <= 0x37 else {
                // GNU writes base-256 for very large values; that is not
                // produced here and a value this large cannot survive the
                // ustar size field anyway, so refuse rather than guess.
                return nil
            }
            sawDigit = true
            value = value * 8 + Int64(byte - 0x30)
        }
        return sawDigit ? value : nil
    }

    static func encodeString(_ string: String, width: Int) -> [UInt8]? {
        let bytes = Array(string.utf8)
        guard bytes.count <= width else { return nil }
        return bytes + [UInt8](repeating: 0, count: width - bytes.count)
    }

    static func decodeString(_ bytes: ArraySlice<UInt8>) -> String {
        let trimmed = bytes.prefix { $0 != 0 }
        return String(decoding: trimmed, as: UTF8.self)
    }

    // MARK: - Header

    struct Header {
        var name: String = ""
        var mode: UInt16 = 0o644
        var uid: Int64 = 0
        var gid: Int64 = 0
        var size: Int64 = 0
        var modificationTime: Int64 = 0
        var type: EntryType = .regular
        var linkName: String = ""

        /// Serialise to exactly one 512-byte block.
        ///
        /// `name` must already fit the name/prefix fields; callers emit a PAX
        /// record first when it does not.
        func encoded() throws -> [UInt8] {
            var block = [UInt8](repeating: 0, count: Tar.blockSize)

            // Split the path across `prefix` and `name` when that is enough to
            // avoid a PAX record. The split must fall on a '/'.
            let (prefix, base) = Tar.splitPath(name)

            guard let prefixBytes = Tar.encodeString(prefix, width: Tar.prefixFieldCapacity),
                  let nameBytes = Tar.encodeString(base, width: Tar.nameFieldCapacity) else {
                throw CryptoError.invalidParameter("tar entry name is too long: \(name)")
            }
            block.replaceSubrange(Tar.Field.prefix, with: prefixBytes)
            block.replaceSubrange(Tar.Field.name, with: nameBytes)

            guard let modeBytes = Tar.encodeOctal(Int64(mode), width: 8),
                  let uidBytes = Tar.encodeOctal(uid, width: 8),
                  let gidBytes = Tar.encodeOctal(gid, width: 8),
                  let sizeBytes = Tar.encodeOctal(size, width: 12),
                  let timeBytes = Tar.encodeOctal(modificationTime, width: 12) else {
                throw CryptoError.invalidParameter("tar header value out of range for \(name)")
            }
            block.replaceSubrange(Tar.Field.mode, with: modeBytes)
            block.replaceSubrange(Tar.Field.uid, with: uidBytes)
            block.replaceSubrange(Tar.Field.gid, with: gidBytes)
            block.replaceSubrange(Tar.Field.size, with: sizeBytes)
            block.replaceSubrange(Tar.Field.modificationTime, with: timeBytes)

            block[156] = type.rawValue

            if !linkName.isEmpty {
                guard let linkBytes = Tar.encodeString(linkName, width: Tar.linkNameFieldCapacity) else {
                    throw CryptoError.invalidParameter("tar link name is too long: \(linkName)")
                }
                block.replaceSubrange(Tar.Field.linkName, with: linkBytes)
            }

            block.replaceSubrange(Tar.Field.magic, with: Tar.posixMagic)
            block.replaceSubrange(Tar.Field.version, with: [0x30, 0x30])  // "00"

            // The checksum is computed with its own field read as spaces.
            for index in Tar.Field.checksum { block[index] = 0x20 }
            let checksum = block.reduce(0) { $0 + Int($1) }
            guard let checksumBytes = Tar.encodeOctal(Int64(checksum), width: 7) else {
                throw CryptoError.invalidParameter("tar checksum overflow")
            }
            block.replaceSubrange(Tar.Field.checksum.lowerBound ..< Tar.Field.checksum.lowerBound + 7,
                                  with: checksumBytes)
            block[Tar.Field.checksum.lowerBound + 7] = 0x20

            return block
        }

        /// Parse one block, or return `nil` for the zero block that ends an
        /// archive.
        static func decode(_ block: [UInt8]) throws -> Header? {
            precondition(block.count == Tar.blockSize)
            if block.allSatisfy({ $0 == 0 }) { return nil }

            let magic = Array(block[Tar.Field.magic])
            guard magic == Tar.posixMagic || magic == Tar.gnuMagic else {
                throw CryptoError.corruptedFile(reason: "the archive contains an entry that is not a tar header.")
            }

            // Verify the checksum before trusting any other field.
            guard let storedChecksum = Tar.decodeOctal(block[Tar.Field.checksum]) else {
                throw CryptoError.corruptedFile(reason: "a tar header has an unreadable checksum.")
            }
            var copy = block
            for index in Tar.Field.checksum { copy[index] = 0x20 }
            let computed = copy.reduce(0) { $0 + Int64($1) }
            guard computed == storedChecksum else {
                throw CryptoError.corruptedFile(
                    reason: "a tar header failed its checksum (stored \(storedChecksum), computed \(computed))."
                )
            }

            guard let size = Tar.decodeOctal(block[Tar.Field.size]),
                  let mode = Tar.decodeOctal(block[Tar.Field.mode]),
                  let mtime = Tar.decodeOctal(block[Tar.Field.modificationTime]) else {
                throw CryptoError.corruptedFile(reason: "a tar header has an unreadable numeric field.")
            }

            let prefix = Tar.decodeString(block[Tar.Field.prefix])
            let base = Tar.decodeString(block[Tar.Field.name])
            let fullName = prefix.isEmpty ? base : prefix + "/" + base

            guard let typeByte = Tar.safeElement(block, Tar.Field.typeFlag.lowerBound),
                  let type = EntryType(rawValue: typeByte) else {
                throw CryptoError.corruptedFile(
                    reason: "a tar header declares an unsupported entry type."
                )
            }

            return Header(
                name: fullName,
                mode: UInt16(truncatingIfNeeded: mode),
                uid: Tar.decodeOctal(block[Tar.Field.uid]) ?? 0,
                gid: Tar.decodeOctal(block[Tar.Field.gid]) ?? 0,
                size: size,
                modificationTime: mtime,
                type: type,
                linkName: Tar.decodeString(block[Tar.Field.linkName])
            )
        }
    }

    /// Bytes of zero padding that follow `size` bytes of content.
    static func paddingLength(for size: Int) -> Int {
        let remainder = size % blockSize
        return remainder == 0 ? 0 : blockSize - remainder
    }

    /// Bounds-checked element access, so a short block cannot crash the parser.
    static func safeElement(_ block: [UInt8], _ index: Int) -> UInt8? {
        index < block.count ? block[index] : nil
    }

    /// Parse an octal string such as the `mode` value in a PAX record.
    static func parseOctalString(_ text: String) -> Int64? {
        var value: Int64 = 0
        var sawDigit = false
        for character in text {
            guard let ascii = character.asciiValue else { return nil }
            if ascii == 0x20 { continue }
            guard ascii >= 0x30, ascii <= 0x37 else { return sawDigit ? value : nil }
            sawDigit = true
            value = value * 8 + Int64(ascii - 0x30)
        }
        return sawDigit ? value : nil
    }

    /// Split a path into the `prefix` and `name` fields at a '/' boundary.
    ///
    /// The base name always goes in `name`; as much leading directory as fits
    /// goes in `prefix`. When the base alone already exceeds the field there is
    /// no valid split, which the caller detects as an encoding failure and
    /// answers with a PAX record.
    static func splitPath(_ path: String) -> (prefix: String, base: String) {
        let bytes = Array(path.utf8)
        if bytes.count <= nameFieldCapacity { return ("", path) }

        // Find the last '/' such that the remainder fits in `name`.
        var splitIndex: String.Index? = nil
        var index = path.startIndex
        while let slash = path[index...].firstIndex(of: "/") {
            let base = path[path.index(after: slash)...]
            let prefix = path[..<slash]
            if base.utf8.count <= nameFieldCapacity && prefix.utf8.count <= prefixFieldCapacity {
                splitIndex = slash
            }
            index = path.index(after: slash)
        }
        guard let splitIndex else { return ("", path) }
        return (String(path[..<splitIndex]), String(path[path.index(after: splitIndex)...]))
    }

    // MARK: - PAX extended headers

    /// Build a PAX record: `"%d %s=%s\n"` where the leading number is the total
    /// length of the record including itself.
    ///
    /// The length depends on its own digit count, so it is solved by iteration;
    /// it converges in two steps for any realistic value.
    static func paxRecord(key: String, value: String) -> Data {
        let body = " \(key)=\(value)\n"
        var digits = 1
        while true {
            let total = digits + body.utf8.count
            let actual = String(total).count
            if actual == digits {
                return Data("\(total)\(body)".utf8)
            }
            digits = actual
        }
    }

    /// Parse a PAX payload into key/value pairs.
    static func parsePaxRecords(_ data: Data) -> [String: String] {
        var records: [String: String] = [:]
        let bytes = [UInt8](data)
        var index = 0

        while index < bytes.count {
            // Read the decimal length prefix.
            var length = 0
            var digits = 0
            while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
                length = length * 10 + Int(bytes[index] - 0x30)
                index += 1
                digits += 1
            }
            guard digits > 0, index < bytes.count, bytes[index] == 0x20 else { return records }

            let recordEnd = index + 1 + (length - digits - 1)
            guard length > digits + 1, recordEnd <= bytes.count else { return records }

            let body = bytes[(index + 1)..<recordEnd]
            if let separator = body.firstIndex(of: 0x3D) {  // '='
                let key = String(decoding: body[body.startIndex..<separator], as: UTF8.self)
                var valueBytes = body[body.index(after: separator)...]
                if valueBytes.last == 0x0A { valueBytes = valueBytes.dropLast() }
                records[key] = String(decoding: valueBytes, as: UTF8.self)
            }
            index = recordEnd
        }
        return records
    }
}

// MARK: - Entry paths

/// Path safety rules shared by the writer and the reader.
///
/// Extraction is the dangerous direction: an archive is untrusted input, and
/// the classic attack is an entry named `../../etc/something` or an entry that
/// writes *through* a symlink created by an earlier entry. Everything that
/// touches the filesystem during extraction goes through these checks.
enum TarPath {

    /// Is this a path we are willing to create on disk?
    ///
    /// Rejects absolute paths, anything containing a `..` component, empty
    /// components, and NUL bytes. A trailing slash is allowed and ignored,
    /// since directories conventionally carry one.
    static func isSafeArchivePath(_ path: String) -> Bool {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\0") else { return false }

        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        for (index, component) in components.enumerated() {
            if component.isEmpty {
                // Only permitted as a single trailing slash.
                if index == components.count - 1, components.count > 1 { continue }
                return false
            }
            if component == "." || component == ".." { return false }
        }
        return true
    }

    /// Normalise a path for comparison: strip a trailing slash.
    static func normalised(_ path: String) -> String {
        var value = path
        while value.hasSuffix("/") { value.removeLast() }
        return value
    }

    /// The ancestor directories of a path, outermost first, excluding the path
    /// itself.
    static func ancestors(of path: String) -> [String] {
        let parts = normalised(path).split(separator: "/").map(String.init)
        guard parts.count > 1 else { return [] }
        return (1..<parts.count).map { parts[0..<$0].joined(separator: "/") }
    }
}
