//
//  PBKDF2.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import CommonCrypto
import Foundation

/// PBKDF2-HMAC-SHA512 via CommonCrypto.
///
/// PBKDF2 is the *slow* part of the chain and the only part that actually
/// resists brute force. HKDF (below) is a fast extract-and-expand step; on its
/// own it is not a password-hardening function, which is exactly why the two
/// are combined rather than used separately.
enum PBKDF2 {

    /// Derive `outputByteCount` bytes from `password` and `salt`.
    ///
    /// The password is passed as raw bytes so that any UTF-8 (including NUL)
    /// is handled correctly — CommonCrypto takes a pointer and a length.
    static func deriveSHA512(
        password: Data,
        salt: Data,
        iterations: UInt32,
        outputByteCount: Int
    ) throws -> Data {
        guard iterations > 0 else {
            throw CryptoError.invalidParameter("The PBKDF2 iteration count must be greater than zero.")
        }
        guard outputByteCount > 0 else {
            throw CryptoError.invalidParameter("The derived key length must be greater than zero.")
        }
        guard !salt.isEmpty else {
            throw CryptoError.invalidParameter("The PBKDF2 salt must not be empty.")
        }

        // CommonCrypto wants an `Int8` pointer for the password. Copying into a
        // dedicated buffer lets us wipe it deterministically afterwards.
        var passwordBuffer = [Int8](repeating: 0, count: max(password.count, 1))
        password.withUnsafeBytes { raw in
            guard let source = raw.bindMemory(to: Int8.self).baseAddress, password.count > 0 else { return }
            passwordBuffer.withUnsafeMutableBufferPointer { destination in
                guard let base = destination.baseAddress else { return }
                base.update(from: source, count: password.count)
            }
        }

        var output = [UInt8](repeating: 0, count: outputByteCount)
        var status: Int32 = Int32(kCCParamError)

        passwordBuffer.withUnsafeBufferPointer { passwordPointer in
            salt.withUnsafeBytes { saltRaw in
                output.withUnsafeMutableBufferPointer { outputPointer in
                    status = CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPointer.baseAddress,
                        password.count,
                        saltRaw.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        iterations,
                        outputPointer.baseAddress,
                        outputByteCount
                    )
                }
            }
        }

        SecureData.zero(&passwordBuffer)

        guard status == kCCSuccess else {
            SecureData.zero(&output)
            throw CryptoError.keyDerivationFailed(status: status)
        }

        let result = Data(output)
        SecureData.zero(&output)
        return result
    }
}
