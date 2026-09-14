//
//  FileCipher.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import CryptoKit
import Foundation

/// Streaming, authenticated file encryption.
///
/// ## Container format
///
/// ```
/// +-------------------------------- 88-byte header (see FileHeader) ----+
/// | magic | ver | kdf | cipher | flags | chunk | iters | size | salt | commit |
/// +--------------------------------------------------------------------+
/// | record 0 | record 1 | ... | record N-1 |
/// +----------------------------------------+
///
/// record i = uint32LE(ciphertextLength) || ciphertext || 16-byte GCM tag
/// ```
///
/// ## How the pieces are bound together
///
/// Each record is sealed with its own nonce and with additional authenticated
/// data (AAD) composed of:
///
/// ```
/// header (all 88 bytes) || uint64BE(recordIndex) || isFinal(1 byte) || uint32LE(ciphertextLength)
/// ```
///
/// That single construction closes every structural attack at once:
///
/// * **Reordering** — record 5 carries `5` inside its AAD, so it cannot be
///   moved to position 2; the tag fails.
/// * **Truncation** — the last record is sealed with `isFinal = 1`. Cut the
///   file short and the decryptor's new "last" record is verified with
///   `isFinal = 0`, so its tag fails. An appended tail has the mirror effect.
/// * **Header tampering** — the header is inside every AAD, so flipping the
///   salt or the work factor breaks the very first record.
/// * **Length-prefix tampering** — the record length is authenticated too.
///
/// ## Nonces
///
/// Nonces are the record index as a big-endian `UInt64` in the low 8 bytes of
/// a 12-byte nonce (an all-zero 4-byte prefix). Reusing `(key, nonce)` would be
/// catastrophic for GCM, and this scheme never does: the AES key is derived
/// from a fresh 32-byte CSPRNG salt on every single encryption, so a given key
/// only ever seals one file's worth of records, each with a distinct index.
public enum FileCipher {

    // MARK: - Public API

    /// Encrypt `inputURL` into `outputURL`.
    ///
    /// The destination is written atomically; on any failure it is left
    /// untouched.
    @discardableResult
    public static func encryptFile(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        options: EncryptionOptions = EncryptionOptions(),
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        let salt = try SecureData.randomBytes(count: FileHeader.saltSize)
        return try encryptFile(
            at: inputURL,
            to: outputURL,
            password: password,
            options: options,
            salt: salt,
            cancellation: cancellation,
            progress: progress,
            phase: phase
        )
    }

    /// The real implementation, with the salt supplied by the caller.
    ///
    /// `internal` on purpose: only the test-suite pins the salt, so it can
    /// compare a container byte-for-byte against an independent
    /// implementation. The public entry point above always draws a fresh
    /// CSPRNG salt, which is what keeps every `(key, nonce)` pair unique.
    @discardableResult
    static func encryptFile(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        options: EncryptionOptions,
        salt: Data,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {

        try validatePaths(input: inputURL, output: outputURL)
        let chunkSize = try validate(options: options)
        let passwordData = try KeyDerivation.normalisedPassword(password)

        let inputSize = try regularFileSize(at: inputURL)
        let reporter = ProgressReporter(callback: progress, phaseCallback: phase)

        // --- key schedule -------------------------------------------------
        reporter.phase(.derivingKey)
        try checkCancellation(cancellation)

        let keys = try KeyDerivation.deriveKeys(
            password: passwordData,
            salt: salt,
            parameters: options.keyDerivation
        )

        var header = FileHeader(
            chunkSize: UInt32(chunkSize),
            salt: salt,
            commitment: Data(),
            keyDerivation: options.keyDerivation
        )
        header.commitment = KeyDerivation.commitment(for: header.prefixBytes(), key: keys.commitmentKey)
        let headerBytes = header.encoded()

        try checkCancellation(cancellation)
        reporter.phase(.processing)

        // --- stream -------------------------------------------------------
        let transaction = try OutputTransaction(destination: outputURL)
        var committed = false
        defer { if !committed { transaction.cleanup() } }

        try transaction.write(headerBytes)

        guard let inputHandle = FileHandle(forReadingAtPath: inputURL.path) else {
            throw CryptoError.ioError("Could not open \"\(inputURL.lastPathComponent)\" for reading.")
        }
        defer { try? inputHandle.close() }

        var index: UInt64 = 0
        var processed: Int64 = 0
        var current = try readUpTo(from: inputHandle, maximum: chunkSize)

        if current.isEmpty {
            // Zero-byte input still produces one authenticated (empty) record,
            // so "empty file" round-trips instead of looking like a truncation.
            try autoreleasepool {
                try seal(
                    plaintext: Data(),
                    index: 0,
                    isFinal: true,
                    headerBytes: headerBytes,
                    key: keys.encryptionKey,
                    transaction: transaction
                )
            }
        } else {
            while true {
                try checkCancellation(cancellation)

                // A record's whole lifetime sits inside one pool. `FileHandle`
                // hands back autoreleased buffers, and without draining them
                // here the process grows to roughly the size of the file it is
                // encrypting.
                let chunkToSeal = current
                let next = try autoreleasepool { () throws -> Data in
                    let following = try readUpTo(from: inputHandle, maximum: chunkSize)
                    try seal(
                        plaintext: chunkToSeal,
                        index: index,
                        isFinal: following.isEmpty,
                        headerBytes: headerBytes,
                        key: keys.encryptionKey,
                        transaction: transaction
                    )
                    return following
                }

                processed += Int64(chunkToSeal.count)
                if inputSize > 0 {
                    reporter.report(Double(processed) / Double(inputSize))
                }

                if next.isEmpty { break }
                current = next
                index += 1
            }
        }

        // --- finalise -----------------------------------------------------
        reporter.phase(.finalizing)
        try checkCancellation(cancellation)

        let permissions = (try? FileManager.default
            .attributesOfItem(atPath: inputURL.path)[.posixPermissions]) as? NSNumber

        try transaction.commit(permissions: permissions)
        committed = true
        reporter.report(1.0, force: true)

        return outputURL
    }

    /// Decrypt `inputURL` into `outputURL`.
    @discardableResult
    public static func decryptFile(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {

        try validatePaths(input: inputURL, output: outputURL)
        let passwordData = try KeyDerivation.normalisedPassword(password)
        let totalSize = try regularFileSize(at: inputURL)

        // The smallest header any supported format can have.
        let smallestHeader = ContainerFormat.allCases.map(\.encodedSize).min() ?? 88
        guard totalSize >= UInt64(smallestHeader) else {
            throw CryptoError.corruptedFile(
                reason: "At \(totalSize) bytes the file is far too small to be a FileCrypt container."
            )
        }

        let reporter = ProgressReporter(callback: progress, phaseCallback: phase)

        guard let inputHandle = FileHandle(forReadingAtPath: inputURL.path) else {
            throw CryptoError.ioError("Could not open \"\(inputURL.lastPathComponent)\" for reading.")
        }
        defer { try? inputHandle.close() }

        // --- header -------------------------------------------------------
        // The magic decides the layout, so read it first and then read exactly
        // as many more bytes as that format uses.
        let magic = try readExactly(from: inputHandle, count: 8)
        guard let format = ContainerFormat.forMagic([UInt8](magic)) else {
            throw CryptoError.notEncryptedFile
        }
        guard totalSize >= UInt64(format.encodedSize) else {
            throw CryptoError.truncatedFile
        }
        var headerData = magic
        headerData.append(try readExactly(from: inputHandle, count: format.encodedSize - 8))
        let header = try FileHeader.decode(headerData)

        // --- key schedule / password check --------------------------------
        reporter.phase(.derivingKey)
        try checkCancellation(cancellation)

        let keys = try KeyDerivation.deriveKeys(
            password: passwordData,
            salt: header.salt,
            parameters: header.keyDerivation
        )

        guard KeyDerivation.isValidCommitment(
            header.commitment,
            prefix: header.prefixBytes(),
            key: keys.commitmentKey
        ) else {
            // Detected with one constant-time HMAC, before touching ciphertext.
            throw CryptoError.wrongPassword
        }

        reporter.phase(.processing)

        // --- stream -------------------------------------------------------
        let transaction = try OutputTransaction(destination: outputURL)
        var committed = false
        defer { if !committed { transaction.cleanup() } }

        let chunkSize = Int(header.chunkSize)
        let headerBytes = header.encoded()
        let maximumRecordSize = UInt32(chunkSize) + UInt32(FileHeader.tagSize)

        var consumed = UInt64(header.encodedSize)
        var index: UInt64 = 0
        var sawFinalRecord = false

        while consumed < totalSize {
            try checkCancellation(cancellation)

            // See the note in `encryptFile`: one pool per record keeps memory
            // flat regardless of how large the container is.
            let isFinal = try autoreleasepool { () throws -> Bool in
                let lengthBytes = try readExactly(from: inputHandle, count: 4)
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
                guard consumed + UInt64(cipherLength) <= totalSize else {
                    throw CryptoError.truncatedFile
                }

                let record = try readExactly(from: inputHandle, count: Int(cipherLength))
                consumed += UInt64(cipherLength)
                let isFinal = consumed >= totalSize

                let nonce = try makeNonce(index: index)
                let aad = makeAdditionalAuthenticatedData(
                    headerBytes: headerBytes,
                    index: index,
                    isFinal: isFinal,
                    cipherLength: cipherLength
                )

                let ciphertext = record.prefix(record.count - FileHeader.tagSize)
                let tag = record.suffix(FileHeader.tagSize)

                let plaintext: Data
                do {
                    let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
                    plaintext = try AES.GCM.open(box, using: keys.encryptionKey, authenticating: aad)
                } catch {
                    throw CryptoError.corruptedFile(
                        reason: "Block \(index + 1) failed authentication. The file was modified, truncated, or is not intact."
                    )
                }

                try transaction.write(plaintext)
                return isFinal
            }

            reporter.report(Double(consumed) / Double(totalSize))

            if isFinal {
                sawFinalRecord = true
                break
            }
            index += 1
        }

        guard sawFinalRecord else {
            throw CryptoError.truncatedFile
        }

        // --- finalise -----------------------------------------------------
        reporter.phase(.finalizing)
        let permissions = (try? FileManager.default
            .attributesOfItem(atPath: inputURL.path)[.posixPermissions]) as? NSNumber

        try transaction.commit(permissions: permissions)
        committed = true
        reporter.report(1.0, force: true)

        return outputURL
    }

    // MARK: - Inspection

    /// Read and validate just the header. Cheap; used by the UI and the CLI.
    public static func readHeader(at url: URL) throws -> FileHeader {
        let size = try regularFileSize(at: url)
        guard size >= 8 else {
            throw CryptoError.notEncryptedFile
        }
        guard let handle = FileHandle(forReadingAtPath: url.path) else {
            throw CryptoError.ioError("Could not open \"\(url.lastPathComponent)\" for reading.")
        }
        defer { try? handle.close() }

        let magic = try readExactly(from: handle, count: 8)
        guard let format = ContainerFormat.forMagic([UInt8](magic)) else {
            throw CryptoError.notEncryptedFile
        }
        guard size >= UInt64(format.encodedSize) else {
            throw CryptoError.truncatedFile
        }

        var data = magic
        data.append(try readExactly(from: handle, count: format.encodedSize - 8))
        return try FileHeader.decode(data)
    }

    /// Does this file start with a FileCrypt magic?
    public static func looksEncrypted(_ url: URL) -> Bool {
        guard let handle = FileHandle(forReadingAtPath: url.path) else { return false }
        defer { try? handle.close() }
        guard let prefix = try? handle.read(upToCount: 8), prefix.count == 8 else { return false }
        return FileHeader.isFileCryptMagic([UInt8](prefix))
    }

    // MARK: - Record sealing

    private static func seal(
        plaintext: Data,
        index: UInt64,
        isFinal: Bool,
        headerBytes: Data,
        key: SymmetricKey,
        transaction: OutputTransaction
    ) throws {
        let nonce = try makeNonce(index: index)
        let cipherLength = UInt32(plaintext.count) + UInt32(FileHeader.tagSize)
        let aad = makeAdditionalAuthenticatedData(
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

        var record = Data()
        record.reserveCapacity(4 + Int(cipherLength))
        record.fcAppendUInt32LE(cipherLength)
        record.append(Data(sealed.ciphertext))
        record.append(Data(sealed.tag))
        try transaction.write(record)
    }

    /// Nonce = 4 zero bytes || big-endian record index.
    private static func makeNonce(index: UInt64) throws -> AES.GCM.Nonce {
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

    private static func makeAdditionalAuthenticatedData(
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

    // MARK: - Validation

    private static func validatePaths(input: URL, output: URL) throws {
        let inputPath = input.standardizedFileURL.resolvingSymlinksInPath().path
        let outputPath = output.standardizedFileURL.resolvingSymlinksInPath().path
        guard inputPath != outputPath else {
            throw CryptoError.inputAndOutputAreSame
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: input.path, isDirectory: &isDirectory) else {
            throw CryptoError.ioError("The file \"\(input.lastPathComponent)\" no longer exists.")
        }
        guard !isDirectory.boolValue else {
            throw CryptoError.ioError("Folders cannot be encrypted. Choose a single file.")
        }

        let directory = output.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: directory.path) else {
            throw CryptoError.ioError("The destination folder \"\(directory.lastPathComponent)\" does not exist.")
        }

        // The destination itself must not already be a directory.
        //
        // Without this the run proceeds all the way to `rename()`, which fails
        // with EISDIR only after the whole file has been through Argon2id and
        // AES-GCM — minutes of work and a full-size temporary file, for a
        // destination that could never have worked. The GUI would be worse
        // still: `fileExists` is true for a directory, so it would first ask
        // the user to confirm replacing it.
        //
        // `fileExists` follows symlinks, so this also rejects a symlink that
        // points at a directory.
        var outputIsDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: output.path, isDirectory: &outputIsDirectory),
           outputIsDirectory.boolValue {
            throw CryptoError.destinationIsDirectory(name: output.lastPathComponent)
        }
    }

    private static func validate(options: EncryptionOptions) throws -> Int {
        let minimum = Int(FileHeader.minimumChunkSize)
        let maximum = Int(FileHeader.maximumChunkSize)
        guard options.chunkSize >= minimum, options.chunkSize <= maximum else {
            throw CryptoError.invalidParameter(
                "Chunk size must be between \(minimum) and \(maximum) bytes."
            )
        }
        guard options.memoryKiB >= Argon2.minimumMemoryKiB,
              options.memoryKiB <= Argon2.maximumMemoryKiB else {
            throw CryptoError.invalidParameter(
                "The Argon2 memory cost must be between \(Argon2.minimumMemoryKiB) KiB and \(Argon2.maximumMemoryKiB) KiB."
            )
        }
        guard Argon2.isMemorySufficient(memoryKiB: options.memoryKiB, parallelism: options.parallelism) else {
            throw CryptoError.invalidParameter("The Argon2 memory cost needs at least 8 KiB per lane.")
        }
        guard options.timeCost >= Argon2.minimumTimeCost,
              options.timeCost <= Argon2.maximumTimeCost else {
            throw CryptoError.invalidParameter(
                "The Argon2 time cost must be between \(Argon2.minimumTimeCost) and \(Argon2.maximumTimeCost)."
            )
        }
        guard options.parallelism >= Argon2.minimumParallelism,
              options.parallelism <= Argon2.maximumParallelism else {
            throw CryptoError.invalidParameter(
                "The Argon2 parallelism must be between \(Argon2.minimumParallelism) and \(Argon2.maximumParallelism)."
            )
        }
        return options.chunkSize
    }

    private static func checkCancellation(_ flag: CancellationFlag?) throws {
        if flag?.isCancelled == true {
            throw CryptoError.cancelled
        }
    }

    private static func regularFileSize(at url: URL) throws -> Int64 {
        do {
            let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
            guard values.isRegularFile == true else {
                throw CryptoError.ioError("\"\(url.lastPathComponent)\" is not a regular file.")
            }
            return Int64(values.fileSize ?? 0)
        } catch let error as CryptoError {
            throw error
        } catch {
            throw CryptoError.ioError("Could not read information about \"\(url.lastPathComponent)\": \(error.localizedDescription)")
        }
    }

    // MARK: - Reading

    /// Read up to `maximum` bytes, returning fewer only at end of file.
    private static func readUpTo(from handle: FileHandle, maximum: Int) throws -> Data {
        var result = Data()
        result.reserveCapacity(min(maximum, 1 << 20))
        while result.count < maximum {
            let remaining = maximum - result.count
            let piece: Data?
            do {
                piece = try handle.read(upToCount: remaining)
            } catch {
                throw CryptoError.ioError("Could not read the input file: \(error.localizedDescription)")
            }
            guard let piece, !piece.isEmpty else { break }
            result.append(piece)
        }
        return result
    }

    /// Read exactly `count` bytes or fail with `.truncatedFile`.
    private static func readExactly(from handle: FileHandle, count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            let remaining = count - result.count
            let piece: Data?
            do {
                piece = try handle.read(upToCount: remaining)
            } catch {
                throw CryptoError.ioError("Could not read the input file: \(error.localizedDescription)")
            }
            guard let piece, !piece.isEmpty else { throw CryptoError.truncatedFile }
            result.append(piece)
        }
        return result
    }
}
