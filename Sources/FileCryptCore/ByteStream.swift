//
//  ByteStream.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// A source of bytes that the cipher pulls from.
///
/// The cipher does not care whether it is reading a file or a `tar` stream
/// being generated on the fly, which is what lets the same record framing,
/// nonce scheme and authentication serve both a single file and a whole folder.
protocol ByteSource {
    /// Return up to `count` bytes, or an empty `Data` at end of input.
    func read(upTo count: Int) throws -> Data
}

/// A destination the cipher pushes bytes to.
protocol ByteSink {
    func write(_ data: Data) throws
}

// MARK: - Files

struct FileByteSource: ByteSource {
    private let handle: FileHandle

    init(url: URL) throws {
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw CryptoError.ioError(
                "Could not open \"\(url.lastPathComponent)\" for reading: \(error.localizedDescription)"
            )
        }
    }

    func read(upTo count: Int) throws -> Data {
        do {
            return try handle.read(upToCount: count) ?? Data()
        } catch {
            throw CryptoError.ioError("Could not read the input file: \(error.localizedDescription)")
        }
    }

    func close() {
        try? handle.close()
    }
}

struct FileByteSink: ByteSink {
    private let handle: FileHandle

    init(url: URL) throws {
        do {
            handle = try FileHandle(forWritingTo: url)
        } catch {
            throw CryptoError.ioError(
                "Could not open \"\(url.lastPathComponent)\" for writing: \(error.localizedDescription)"
            )
        }
    }

    func write(_ data: Data) throws {
        guard !data.isEmpty else { return }
        do {
            try handle.write(contentsOf: data)
        } catch {
            throw CryptoError.ioError("Could not write the output file: \(error.localizedDescription)")
        }
    }

    func close() {
        try? handle.close()
    }
}

// MARK: - In-memory adapters

/// Serves a fixed block of bytes. Used for tests and for small payloads.
final class DataByteSource: ByteSource {
    private var remaining: Data

    init(_ data: Data) {
        self.remaining = data
    }

    func read(upTo count: Int) throws -> Data {
        guard !remaining.isEmpty else { return Data() }
        let take = min(count, remaining.count)
        let chunk = Data(remaining.prefix(take))
        remaining.removeFirst(take)
        return chunk
    }
}

/// Accumulates everything written to it.
final class DataByteSink: ByteSink {
    private(set) var data = Data()

    func write(_ data: Data) throws {
        self.data.append(data)
    }
}

// MARK: - Composite

/// A source that yields several chunks in order.
final class ChunkByteSource: ByteSource {
    private var chunks: [Data]
    private var offset = 0

    init(_ chunks: [Data]) {
        self.chunks = chunks
    }

    func read(upTo count: Int) throws -> Data {
        var result = Data()
        while result.count < count, !chunks.isEmpty {
            let head = chunks[0]
            let take = min(count - result.count, head.count - offset)
            result.append(head[offset..<(offset + take)])
            offset += take
            if offset == head.count {
                chunks.removeFirst()
                offset = 0
            }
        }
        return result
    }
}
