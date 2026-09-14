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
    /// A directory is archived first; a regular file is streamed as-is. The
    /// destination is written atomically, so on any failure it is left
    /// untouched.
    @discardableResult
    public static func encrypt(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        options: EncryptionOptions = EncryptionOptions(),
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        try validatePaths(input: inputURL, output: outputURL, allowDirectoryInput: true)

        var isDirectory: ObjCBool = false
        FileManager.default.fileExists(atPath: inputURL.path, isDirectory: &isDirectory)

        if isDirectory.boolValue {
            return try encryptDirectory(
                at: inputURL, to: outputURL, password: password, options: options,
                cancellation: cancellation, progress: progress, phase: phase
            )
        }
        return try encryptFile(
            at: inputURL, to: outputURL, password: password, options: options,
            cancellation: cancellation, progress: progress, phase: phase
        )
    }

    /// Encrypt a single regular file.
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
            at: inputURL, to: outputURL, password: password, options: options,
            salt: salt, cancellation: cancellation, progress: progress, phase: phase
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
        try validatePaths(input: inputURL, output: outputURL, allowDirectoryInput: false)
        let chunkSize = try validate(options: options)
        let passwordData = try KeyDerivation.normalisedPassword(password)
        let inputSize = try regularFileSize(at: inputURL)
        let reporter = ProgressReporter(callback: progress, phaseCallback: phase)

        return try encryptContainer(
            to: outputURL,
            passwordData: passwordData,
            options: options,
            salt: salt,
            chunkSize: chunkSize,
            containsDirectoryArchive: false,
            permissions: (try? FileManager.default
                .attributesOfItem(atPath: inputURL.path)[.posixPermissions]) as? NSNumber,
            totalSize: inputSize,
            cancellation: cancellation,
            reporter: reporter
        ) { sink in
            let source = try FileByteSource(url: inputURL)
            defer { source.close() }

            var processed: Int64 = 0
            while true {
                try checkCancellation(cancellation)
                // Read *and* seal inside one pool: `FileHandle` and the
                // AEAD both hand back autoreleased buffers, and without this
                // the process grows with the file.
                let chunk = try autoreleasepool { () -> Data in
                    let data = try source.read(upTo: chunkSize)
                    if !data.isEmpty { try sink.write(data) }
                    return data
                }
                if chunk.isEmpty { break }
                processed += Int64(chunk.count)
                if inputSize > 0 {
                    reporter.report(Double(processed) / Double(inputSize))
                }
            }
        }
    }

    /// Encrypt a directory as a single container holding a `tar` archive.
    @discardableResult
    public static func encryptDirectory(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        options: EncryptionOptions = EncryptionOptions(),
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        let salt = try SecureData.randomBytes(count: FileHeader.saltSize)
        return try encryptDirectory(
            at: inputURL, to: outputURL, password: password, options: options, salt: salt,
            cancellation: cancellation, progress: progress, phase: phase
        )
    }

    @discardableResult
    static func encryptDirectory(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        options: EncryptionOptions,
        salt: Data,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        try validatePaths(input: inputURL, output: outputURL, allowDirectoryInput: true)
        let chunkSize = try validate(options: options)
        let passwordData = try KeyDerivation.normalisedPassword(password)
        let reporter = ProgressReporter(callback: progress, phaseCallback: phase)

        // Walk first so progress has a denominator and so an unreadable file
        // deep in the tree fails before anything is written.
        let survey = try TarWriter.survey(root: inputURL)

        return try encryptContainer(
            to: outputURL,
            passwordData: passwordData,
            options: options,
            salt: salt,
            chunkSize: chunkSize,
            containsDirectoryArchive: true,
            // A folder has no single mode; each entry's mode is stored in the
            // archive and restored on extraction instead.
            permissions: nil,
            totalSize: survey.totalBytes,
            cancellation: cancellation,
            reporter: reporter
        ) { sink in
            let writer = TarWriter(root: inputURL) { chunk in
                try checkCancellation(cancellation)
                try sink.write(chunk)
            }
            try writer.write(archiveRootName: inputURL.lastPathComponent)
        }
    }

    /// Shared prologue: derive the key, build the header, and hand a sealing
    /// sink to a closure that produces the plaintext.
    private static func encryptContainer(
        to outputURL: URL,
        passwordData: Data,
        options: EncryptionOptions,
        salt: Data,
        chunkSize: Int,
        containsDirectoryArchive: Bool,
        permissions: NSNumber?,
        totalSize: Int64,
        cancellation: CancellationFlag?,
        reporter: ProgressReporter,
        produce: (EncryptingByteSink) throws -> Void
    ) throws -> URL {
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
            keyDerivation: options.keyDerivation,
            flags: containsDirectoryArchive ? FileHeader.Flag.directoryArchive : 0
        )
        header.commitment = KeyDerivation.commitment(for: header.prefixBytes(), key: keys.commitmentKey)
        let headerBytes = header.encoded()

        try checkCancellation(cancellation)
        reporter.phase(.processing)

        let transaction = try OutputTransaction(destination: outputURL)
        var committed = false
        defer { if !committed { transaction.cleanup() } }

        try transaction.write(headerBytes)

        let sink = EncryptingByteSink(
            headerBytes: headerBytes,
            key: keys.encryptionKey,
            chunkSize: chunkSize,
            output: transaction
        )
        try produce(sink)
        try sink.finish()

        reporter.phase(.finalizing)
        try checkCancellation(cancellation)

        try transaction.commit(permissions: permissions)
        committed = true
        reporter.report(1.0, force: true)
        _ = totalSize
        return outputURL
    }

    /// Decrypt a container, writing a file or extracting a folder depending on
    /// what the header says it holds.
    @discardableResult
    public static func decrypt(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        let header = try readHeader(at: inputURL)
        if header.containsDirectoryArchive {
            return try decryptDirectory(
                at: inputURL, to: outputURL, password: password,
                cancellation: cancellation, progress: progress, phase: phase
            )
        }
        return try decryptFile(
            at: inputURL, to: outputURL, password: password,
            cancellation: cancellation, progress: progress, phase: phase
        )
    }

    /// Decrypt a container that holds a single file's bytes.
    @discardableResult
    public static func decryptFile(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        try validatePaths(input: inputURL, output: outputURL, allowDirectoryInput: false)

        let transaction = try OutputTransaction(destination: outputURL)
        var committed = false
        defer { if !committed { transaction.cleanup() } }

        try openContainer(
            at: inputURL, password: password, cancellation: cancellation,
            progress: progress, phase: phase
        ) { plaintext, reporter, totalSize in
            while true {
                try checkCancellation(cancellation)
                let chunk = try autoreleasepool { () -> Data in
                    let data = try plaintext.read(upTo: 1 << 20)
                    if !data.isEmpty { try transaction.write(data) }
                    return data
                }
                if chunk.isEmpty { break }
                reporter.report(Double(plaintext.bytesConsumed) / Double(max(totalSize, 1)))
            }
            // A stream that merely stops being read cannot tell "finished"
            // from "truncated"; this is what distinguishes them.
            try plaintext.verifyComplete()
        }

        // The container's mode is not the plaintext's; the caller restores the
        // original permissions itself when it knows them.
        try transaction.commit(permissions: nil)
        progress?(1.0)
        committed = true
        return outputURL
    }

    /// Decrypt a container that holds an archived folder, extracting it to
    /// `outputURL`.
    @discardableResult
    public static func decryptDirectory(
        at inputURL: URL,
        to outputURL: URL,
        password: String,
        cancellation: CancellationFlag? = nil,
        progress: ((Double) -> Void)? = nil,
        phase: ((FileCipherPhase) -> Void)? = nil
    ) throws -> URL {
        try validatePaths(
            input: inputURL, output: outputURL,
            allowDirectoryInput: false, allowDirectoryOutput: true
        )

        // Extract into a sibling staging directory and move it into place only
        // once the whole archive has authenticated, so a tampered container
        // cannot leave a half-populated folder behind.
        let parent = outputURL.deletingLastPathComponent()
        let staging = parent.appendingPathComponent(
            ".\(outputURL.lastPathComponent).fcrypt-\(UUID().uuidString).partial"
        )
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
        var committed = false
        defer { if !committed { try? FileManager.default.removeItem(at: staging) } }

        try openContainer(
            at: inputURL, password: password, cancellation: cancellation,
            progress: progress, phase: phase
        ) { plaintext, reporter, totalSize in
            let reader = TarReader { try autoreleasepool { try plaintext.read(upTo: 1 << 20) } }
            _ = try TarExtractor.extract(reader: reader, to: staging) { _ in
                reporter.report(Double(plaintext.bytesConsumed) / Double(max(totalSize, 1)))
            }
            try plaintext.verifyComplete()
        }

        // The caller names the folder, so the archive's own top-level entry is
        // unwrapped rather than nested inside it: decrypting `Project.fcrypt`
        // to `Restored` should give `Restored/README.md`, not
        // `Restored/Project/README.md`. That matches how the output path is
        // treated for a single file.
        var source = staging
        let contents = try FileManager.default.contentsOfDirectory(atPath: staging.path)
        if contents.count == 1 {
            let only = staging.appendingPathComponent(contents[0])
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: only.path, isDirectory: &isDirectory),
               isDirectory.boolValue {
                source = only
            }
        }

        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }
        do {
            try FileManager.default.moveItem(at: source, to: outputURL)
        } catch {
            throw CryptoError.ioError(
                "Could not move the extracted folder into place: \(error.localizedDescription)"
            )
        }
        committed = true
        progress?(1.0)
        return outputURL
    }

    /// Shared prologue for both decryption paths: read the header, derive the
    /// key, verify the commitment, and hand a plaintext source to a closure.
    private static func openContainer(
        at inputURL: URL,
        password: String,
        cancellation: CancellationFlag?,
        progress: ((Double) -> Void)?,
        phase: ((FileCipherPhase) -> Void)?,
        consume: (DecryptingByteSource, ProgressReporter, Int64) throws -> Void
    ) throws {
        let passwordData = try KeyDerivation.normalisedPassword(password)
        let totalSize = try regularFileSize(at: inputURL)
        let reporter = ProgressReporter(callback: progress, phaseCallback: phase)

        let smallestHeader = ContainerFormat.allCases.map(\.encodedSize).min() ?? 88
        guard totalSize >= UInt64(smallestHeader) else {
            throw CryptoError.corruptedFile(
                reason: "At \(totalSize) bytes the file is far too small to be a FileCrypt container."
            )
        }

        let source = try FileByteSource(url: inputURL)
        defer { source.close() }

        let magic = try readExactly(from: source, count: 8)
        guard let format = ContainerFormat.forMagic([UInt8](magic)) else {
            throw CryptoError.notEncryptedFile
        }
        guard totalSize >= UInt64(format.encodedSize) else { throw CryptoError.truncatedFile }

        var headerData = magic
        headerData.append(try readExactly(from: source, count: format.encodedSize - 8))
        let header = try FileHeader.decode(headerData)

        reporter.phase(.derivingKey)
        try checkCancellation(cancellation)

        let keys = try KeyDerivation.deriveKeys(
            password: passwordData, salt: header.salt, parameters: header.keyDerivation
        )

        guard KeyDerivation.isValidCommitment(
            header.commitment, prefix: header.prefixBytes(), key: keys.commitmentKey
        ) else {
            // Detected with one constant-time HMAC, before touching ciphertext.
            throw CryptoError.wrongPassword
        }

        reporter.phase(.processing)

        let plaintext = DecryptingByteSource(
            source: source,
            header: header,
            key: keys.encryptionKey,
            headerSize: header.encodedSize,
            totalSize: totalSize
        )
        try consume(plaintext, reporter, totalSize)
    }

    // MARK: - Inspection

    /// Read and validate just the header. Cheap; used by the UI and the CLI.
    public static func readHeader(at url: URL) throws -> FileHeader {
        let size = try regularFileSize(at: url)
        guard size >= 8 else { throw CryptoError.notEncryptedFile }

        let source = try FileByteSource(url: url)
        defer { source.close() }

        let magic = try readExactly(from: source, count: 8)
        guard let format = ContainerFormat.forMagic([UInt8](magic)) else {
            throw CryptoError.notEncryptedFile
        }
        guard size >= UInt64(format.encodedSize) else { throw CryptoError.truncatedFile }

        var data = magic
        data.append(try readExactly(from: source, count: format.encodedSize - 8))
        return try FileHeader.decode(data)
    }

    /// Does this file start with a FileCrypt magic?
    public static func looksEncrypted(_ url: URL) -> Bool {
        let source = try? FileByteSource(url: url)
        guard let source else { return false }
        defer { source.close() }
        guard let prefix = try? source.read(upTo: 8), prefix.count == 8 else { return false }
        return FileHeader.isFileCryptMagic([UInt8](prefix))
    }

    /// Is this container an archived folder?
    public static func containsDirectory(_ url: URL) -> Bool {
        (try? readHeader(at: url))?.containsDirectoryArchive ?? false
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

    private static func validatePaths(
        input: URL,
        output: URL,
        allowDirectoryInput: Bool,
        allowDirectoryOutput: Bool = false
    ) throws {
        let inputPath = input.standardizedFileURL.resolvingSymlinksInPath().path
        let outputPath = output.standardizedFileURL.resolvingSymlinksInPath().path
        guard inputPath != outputPath else {
            throw CryptoError.inputAndOutputAreSame
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: input.path, isDirectory: &isDirectory) else {
            throw CryptoError.ioError("The file \"\(input.lastPathComponent)\" no longer exists.")
        }
        if isDirectory.boolValue, !allowDirectoryInput {
            throw CryptoError.ioError("That is a folder. Use the folder action to encrypt it.")
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
        //
        // Only when the result is meant to be a file, though: restoring a
        // folder archive into an existing folder is the ordinary overwrite
        // case, not a mistake.
        if !allowDirectoryOutput {
            var outputIsDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: output.path, isDirectory: &outputIsDirectory),
               outputIsDirectory.boolValue {
                throw CryptoError.destinationIsDirectory(name: output.lastPathComponent)
            }
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

    /// Read exactly `count` bytes from a source, or fail with `.truncatedFile`.
    static func readExactly(from source: ByteSource, count: Int) throws -> Data {
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
