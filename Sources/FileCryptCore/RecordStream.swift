//
//  RecordStream.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import CryptoKit
import Foundation

/// Seals plaintext into authenticated records on the way to a sink.
///
/// This is the whole of the container's framing, extracted so that a single
/// file and a generated `tar` stream go through exactly the same code. Anything
/// that writes plaintext here gets the same nonce derivation, the same
/// additional authenticated data, and therefore the same guarantees.
final class EncryptingByteSink: ByteSink {

    private let headerBytes: Data
    private let key: SymmetricKey
    private let chunkSize: Int
    private let output: ByteSink

    /// Holds less than one chunk between calls. Never grown and trimmed: see
    /// `write(_:)`.
    private var pending = Data()
    private var index: UInt64 = 0
    private var finished = false

    init(headerBytes: Data, key: SymmetricKey, chunkSize: Int, output: ByteSink) {
        self.headerBytes = headerBytes
        self.key = key
        self.chunkSize = chunkSize
        self.output = output
    }

    func write(_ data: Data) throws {
        guard !finished else { throw CryptoError.ioError("The output stream is already finished.") }
        guard !data.isEmpty else { return }

        var remaining = data[...]

        // A chunk is sealed only once a *further* byte has arrived, so the last
        // record is the one that carries `isFinal`. Sealing at exactly
        // chunkSize would emit a trailing empty record whenever the input is an
        // exact multiple of the chunk size.
        //
        // This deliberately never does `removeFirst` on a growing buffer. `Data`
        // does not release the consumed prefix, so that pattern makes resident
        // memory climb with the file — a 512 MiB input cost 522 MiB before this
        // was rewritten.
        while pending.count + remaining.count > chunkSize {
            var chunk = pending
            let take = chunkSize - pending.count
            chunk.append(contentsOf: remaining.prefix(take))
            remaining = remaining.dropFirst(take)
            pending = Data()
            try seal(chunk, isFinal: false)
        }

        if !remaining.isEmpty {
            pending.append(contentsOf: remaining)
        }
    }

    /// Seal whatever is left as the final record and flush.
    ///
    /// An empty input still produces one authenticated empty record, so an
    /// empty file or folder round-trips instead of looking like a truncation.
    func finish() throws {
        guard !finished else { return }
        finished = true
        try seal(pending, isFinal: true)
        pending = Data()
    }

    private func seal(_ plaintext: Data, isFinal: Bool) throws {
        let nonce = try RecordStream.nonce(index: index)
        let cipherLength = UInt32(plaintext.count) + UInt32(FileHeader.tagSize)
        let aad = RecordStream.additionalAuthenticatedData(
            headerBytes: headerBytes,
            index: index,
            isFinal: isFinal,
            cipherLength: cipherLength
        )

        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        } catch {
            throw CryptoError.encryptionFailed(error.localizedDescription)
        }

        var record = Data(capacity: 4 + Int(cipherLength))
        record.fcAppendUInt32LE(cipherLength)
        record.append(Data(sealed.ciphertext))
        record.append(Data(sealed.tag))
        try output.write(record)

        index += 1
    }
}

/// Decrypts a record stream on demand, presenting the plaintext as a source.
///
/// Pulling rather than pushing is what lets the `tar` reader consume the
/// plaintext directly. The alternative — decrypting the archive to a temporary
/// file and extracting from that — would leave the entire folder sitting
/// unencrypted on disk, which rather defeats the point.
final class DecryptingByteSource: ByteSource {

    private let source: ByteSource
    private let headerBytes: Data
    private let key: SymmetricKey
    private let totalSize: Int64
    private let chunkSize: Int
    private let maximumRecordSize: UInt32

    private var plaintext = Data()
    private var plaintextOffset = 0
    private var consumed: Int64
    private var index: UInt64 = 0
    private var sawFinalRecord = false
    private var reachedEnd = false

    /// Number of bytes of container consumed, for progress reporting.
    private(set) var bytesConsumed: Int64

    init(
        source: ByteSource,
        header: FileHeader,
        key: SymmetricKey,
        headerSize: Int,
        totalSize: Int64
    ) {
        self.source = source
        self.headerBytes = header.encoded()
        self.key = key
        self.chunkSize = Int(header.chunkSize)
        self.maximumRecordSize = UInt32(header.chunkSize) + UInt32(FileHeader.tagSize)
        self.totalSize = totalSize
        self.consumed = Int64(headerSize)
        self.bytesConsumed = Int64(headerSize)
    }

    func read(upTo count: Int) throws -> Data {
        while plaintext.count - plaintextOffset < count, !reachedEnd {
            try readNextRecord()
        }
        let available = plaintext.count - plaintextOffset
        guard available > 0 else { return Data() }

        let take = min(count, available)
        let chunk = Data(plaintext[plaintextOffset..<(plaintextOffset + take)])
        plaintextOffset += take

        // Compact rather than trim: `removeFirst` would keep the whole buffer
        // alive and make memory scale with the container.
        if plaintextOffset == plaintext.count {
            plaintext = Data()
            plaintextOffset = 0
        } else if plaintextOffset >= 1 << 20 {
            plaintext = Data(plaintext.dropFirst(plaintextOffset))
            plaintextOffset = 0
        }
        return chunk
    }

    /// Verify that the stream ended the way it must.
    ///
    /// Called by the consumer once it has finished reading, because a stream
    /// that simply stops being read cannot tell "done" from "truncated".
    func verifyComplete() throws {
        // Drain so the final record is seen.
        while !reachedEnd {
            _ = try read(upTo: 1 << 16)
        }
        guard sawFinalRecord else { throw CryptoError.truncatedFile }
    }

    private func readNextRecord() throws {
        if consumed >= totalSize {
            reachedEnd = true
            return
        }

        let lengthBytes = try readExactly(from: source, count: 4)
        consumed += 4
        let cipherLength = ByteCoding.readUInt32LE([UInt8](lengthBytes), at: 0)

        guard cipherLength >= UInt32(FileHeader.tagSize) else {
            throw CryptoError.corruptedFile(
                reason: "Record \(index) is shorter than its own authentication tag."
            )
        }
        guard cipherLength <= maximumRecordSize else {
            throw CryptoError.corruptedFile(
                reason: "Record \(index) claims \(cipherLength) bytes, more than the header's chunk size allows."
            )
        }
        guard consumed + Int64(cipherLength) <= totalSize else {
            throw CryptoError.truncatedFile
        }

        let record = try readExactly(from: source, count: Int(cipherLength))
        consumed += Int64(cipherLength)
        let isFinal = consumed >= totalSize

        let nonce = try RecordStream.nonce(index: index)
        let aad = RecordStream.additionalAuthenticatedData(
            headerBytes: headerBytes,
            index: index,
            isFinal: isFinal,
            cipherLength: cipherLength
        )

        let ciphertext = record.prefix(record.count - FileHeader.tagSize)
        let tag = record.suffix(FileHeader.tagSize)

        do {
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            plaintext.append(try AES.GCM.open(box, using: key, authenticating: aad))
        } catch {
            throw CryptoError.corruptedFile(
                reason: "Block \(index + 1) failed authentication. The file was modified, truncated, or is not intact."
            )
        }

        if isFinal {
            sawFinalRecord = true
            reachedEnd = true
        }
        index += 1
    }

    private func readExactly(from source: ByteSource, count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            let piece = try source.read(upTo: count - result.count)
            guard !piece.isEmpty else { throw CryptoError.truncatedFile }
            result.append(piece)
        }
        return result
    }
}

/// Nonce and AAD construction, shared by both directions.
///
/// These must agree exactly; keeping them in one place is what makes it hard to
/// change one without the other.
enum RecordStream {

    /// Nonce = 4 zero bytes ‖ big-endian record index.
    static func nonce(index: UInt64) throws -> AES.GCM.Nonce {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(FileHeader.nonceSize)
        bytes.append(contentsOf: [0, 0, 0, 0])
        ByteCoding.appendUInt64BE(index, to: &bytes)
        do {
            return try AES.GCM.Nonce(data: Data(bytes))
        } catch {
            throw CryptoError.encryptionFailed("Could not build a nonce for record \(index).")
        }
    }

    /// header ‖ uint64be(index) ‖ isFinal ‖ uint32le(cipherLength)
    static func additionalAuthenticatedData(
        headerBytes: Data,
        index: UInt64,
        isFinal: Bool,
        cipherLength: UInt32
    ) -> Data {
        var bytes = [UInt8](headerBytes)
        ByteCoding.appendUInt64BE(index, to: &bytes)
        bytes.append(isFinal ? 1 : 0)
        ByteCoding.appendUInt32LE(cipherLength, to: &bytes)
        return Data(bytes)
    }
}
