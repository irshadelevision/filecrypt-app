//
//  OutputTransaction.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Writes the result to a hidden temporary file next to the destination and
/// only renames it into place once the whole operation succeeded.
///
/// This is what makes a failed or cancelled run harmless:
/// * a wrong password, a corrupt block or a full disk never leaves a
///   half-written file where the user's data used to be,
/// * the rename is atomic, so a crash mid-run cannot produce a torn output,
/// * an existing destination is only replaced at the very last moment.
final class OutputTransaction {

    private let destination: URL
    private let temporaryURL: URL
    private var handle: FileHandle?
    private var finished = false

    init(destination: URL) throws {
        self.destination = destination

        let directory = destination.deletingLastPathComponent()
        let temporaryName = ".\(destination.lastPathComponent).fcrypt-\(UUID().uuidString).part"
        self.temporaryURL = directory.appendingPathComponent(temporaryName)

        // 0600: while the plaintext is in flight it is readable only by us.
        let created = FileManager.default.createFile(
            atPath: temporaryURL.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        )
        guard created else {
            throw CryptoError.ioError(
                "Could not create a temporary file in \"\(directory.lastPathComponent)\". Check that you can write to that folder."
            )
        }

        do {
            self.handle = try FileHandle(forWritingTo: temporaryURL)
        } catch {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw CryptoError.ioError("Could not open the temporary file for writing: \(error.localizedDescription)")
        }
    }

    func write(_ data: Data) throws {
        guard !data.isEmpty else { return }
        guard let handle else {
            throw CryptoError.ioError("The output file is already closed.")
        }
        do {
            try handle.write(contentsOf: data)
        } catch {
            throw CryptoError.ioError("Could not write the output file: \(error.localizedDescription)")
        }
    }

    /// Flush, close, restore permissions and atomically move into place.
    func commit(permissions: NSNumber?) throws {
        if let handle {
            do {
                try handle.synchronize()
            } catch {
                // `synchronize` is a durability hint; a failure here is not
                // fatal, the subsequent close still surfaces real errors.
            }
            do {
                try handle.close()
            } catch {
                self.handle = nil
                throw CryptoError.ioError("Could not finish writing the output file: \(error.localizedDescription)")
            }
        }
        handle = nil

        if let permissions {
            try? FileManager.default.setAttributes(
                [.posixPermissions: permissions],
                ofItemAtPath: temporaryURL.path
            )
        }

        // POSIX `rename` is atomic and silently replaces the target, which is
        // exactly the semantics we want (no window where the destination is
        // missing, unlike remove-then-move).
        let result: Int32 = temporaryURL.withUnsafeFileSystemRepresentation { source in
            guard let source else { return -1 }
            return destination.withUnsafeFileSystemRepresentation { target in
                guard let target else { return -1 }
                return rename(source, target)
            }
        }

        guard result == 0 else {
            let message = String(cString: strerror(errno))
            throw CryptoError.ioError("Could not move the finished file into place: \(message)")
        }
        finished = true
    }

    /// Remove the temporary file. Safe to call more than once.
    func cleanup() {
        if let handle {
            try? handle.close()
        }
        handle = nil
        if !finished {
            try? FileManager.default.removeItem(at: temporaryURL)
        }
    }
}
