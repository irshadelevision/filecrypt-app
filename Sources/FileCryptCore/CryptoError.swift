//
//  CryptoError.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Every failure the crypto core can produce.
///
/// The enum is `Equatable` so that tests (and the UI) can react to specific
/// cases such as `.cancelled` or `.wrongPassword` without string matching.
public enum CryptoError: Error, LocalizedError, Equatable {
    /// The user asked to stop, or the host task was cancelled.
    case cancelled
    /// The password was empty (or became empty after Unicode normalisation).
    case emptyPassword
    /// The password exceeded the maximum supported byte length.
    case passwordTooLong(max: Int)
    /// A general argument problem (chunk size, iteration count, ...).
    case invalidParameter(String)
    /// The container magic bytes did not match.
    case notEncryptedFile
    /// The container is a FileCrypt file, but one we cannot read.
    case unsupportedFormat(reason: String)
    /// The container is structurally damaged, or an authentication tag failed.
    case corruptedFile(reason: String)
    /// The file ended earlier than its own framing said it should.
    case truncatedFile
    /// The key commitment did not verify: the password is wrong.
    case wrongPassword
    /// Input and output resolved to the same path.
    case inputAndOutputAreSame
    /// The destination path is an existing directory.
    case destinationIsDirectory(name: String)
    /// The random number generator refused to produce bytes.
    case randomGenerationFailed
    /// The platform KDF returned a failure status.
    case keyDerivationFailed(status: Int32)
    /// Argon2 refused the parameters, or could not run.
    case argon2Failed(reason: String)
    /// AES-GCM could not seal a block.
    case encryptionFailed(String)
    /// Anything that went wrong while touching the filesystem.
    case ioError(String)

    public var errorDescription: String? {
        switch self {
        case .cancelled:
            return "The operation was cancelled."
        case .emptyPassword:
            return "The password is empty."
        case .passwordTooLong(let max):
            return "The password is too long. The limit is \(max) UTF-8 bytes."
        case .invalidParameter(let reason):
            return reason
        case .notEncryptedFile:
            return "This is not a FileCrypt file."
        case .unsupportedFormat(let reason):
            return "Unsupported FileCrypt file: \(reason)"
        case .corruptedFile(let reason):
            return "The file failed its integrity check. \(reason)"
        case .truncatedFile:
            return "The file is incomplete. It was truncated or is still being written."
        case .wrongPassword:
            return "The password is incorrect, or the file has been modified."
        case .inputAndOutputAreSame:
            return "The source and destination are the same file."
        case .destinationIsDirectory(let name):
            return "\"\(name)\" is a folder. Choose a file name for the result, not a folder."
        case .randomGenerationFailed:
            return "The system could not produce secure random bytes."
        case .keyDerivationFailed(let status):
            return "Key derivation failed (status \(status))."
        case .argon2Failed(let reason):
            return "Key derivation failed. \(reason)"
        case .encryptionFailed(let reason):
            return "Encryption failed. \(reason)"
        case .ioError(let reason):
            return reason
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .wrongPassword:
            return "Check the password and try again. FileCrypt cannot recover a lost password."
        case .corruptedFile, .truncatedFile:
            return "Restore the file from a backup if you have one."
        case .notEncryptedFile:
            return "Switch to Encrypt mode, or pick a file that ends in .fcrypt."
        case .argon2Failed:
            return "The file itself is fine; only the Argon2 parameters were a problem."
        case .destinationIsDirectory:
            return "Pick a different name, or choose another folder."
        case .cancelled:
            return nil
        default:
            return nil
        }
    }
}
