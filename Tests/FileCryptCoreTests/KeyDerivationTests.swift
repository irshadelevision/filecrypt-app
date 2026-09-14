//
//  KeyDerivationTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import CryptoKit
import Foundation
import XCTest

@testable import FileCryptCore

/// Known-answer tests for the primitives, so a regression in the key schedule
/// is caught here rather than showing up as "old files no longer open".
///
/// Vectors come from RFC 6070-style PBKDF2-HMAC-SHA512 listings and RFC 5869
/// (HKDF) test case 1.
final class KeyDerivationTests: XCTestCase {

    // MARK: - PBKDF2-HMAC-SHA512

    func testPBKDF2SHA512MatchesKnownVectors() throws {
        let vectors: [(iterations: UInt32, expected: String)] = [
            (1, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
                + "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"),
            (2, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
                + "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"),
            (4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
                + "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5")
        ]

        for vector in vectors {
            let derived = try PBKDF2.deriveSHA512(
                password: Data("password".utf8),
                salt: Data("salt".utf8),
                iterations: vector.iterations,
                outputByteCount: 64
            )
            XCTAssertEqual(
                derived.hexDescription,
                vector.expected,
                "PBKDF2-HMAC-SHA512 mismatch at \(vector.iterations) iterations"
            )
        }
    }

    func testPBKDF2HandlesEmbeddedNullBytes() throws {
        // "pass\0word" / "sa\0lt" at 4096 rounds, 32 bytes.
        let derived = try PBKDF2.deriveSHA512(
            password: Data([0x70, 0x61, 0x73, 0x73, 0x00, 0x77, 0x6F, 0x72, 0x64]),
            salt: Data([0x73, 0x61, 0x00, 0x6C, 0x74]),
            iterations: 4096,
            outputByteCount: 32
        )
        XCTAssertEqual(derived.hexDescription, "9d9e9c4cd21fe4be24d5b8244c759665f39d98fc12a9ca759bb021db3cfadf34")
    }

    func testPBKDF2RejectsZeroIterations() {
        XCTAssertThrowsError(
            try PBKDF2.deriveSHA512(
                password: Data("x".utf8),
                salt: Data("salt".utf8),
                iterations: 0,
                outputByteCount: 32
            )
        ) { error in
            guard case CryptoError.invalidParameter = error else {
                return XCTFail("expected .invalidParameter, got \(error)")
            }
        }
    }

    func testPBKDF2RejectsEmptySalt() {
        XCTAssertThrowsError(
            try PBKDF2.deriveSHA512(
                password: Data("x".utf8),
                salt: Data(),
                iterations: 1000,
                outputByteCount: 32
            )
        )
    }

    // MARK: - HKDF-SHA256 (RFC 5869 test case 1)

    func testHKDFSHA256MatchesRFC5869TestCase1() {
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = Data(Array(UInt8(0x00)...UInt8(0x0c)))
        let info = Data(Array(UInt8(0xf0)...UInt8(0xf9)))

        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: 42
        )
        let bytes = key.withUnsafeBytes { Data($0) }

        XCTAssertEqual(
            bytes.hexDescription,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    }

    // MARK: - Key schedule properties

    func testDerivedKeysAreDeterministicForSameInputs() throws {
        let salt = Data(repeating: 0x5A, count: 32)
        let first = try KeyDerivation.deriveKeys(password: Data("hunter2".utf8), salt: salt, parameters: .pbkdf2SHA512(iterations: 1_000))
        let second = try KeyDerivation.deriveKeys(password: Data("hunter2".utf8), salt: salt, parameters: .pbkdf2SHA512(iterations: 1_000))

        XCTAssertEqual(
            first.encryptionKey.withUnsafeBytes { Data($0) },
            second.encryptionKey.withUnsafeBytes { Data($0) }
        )
    }

    func testEncryptionAndCommitmentKeysAreIndependent() throws {
        // Domain separation: the two subkeys must never coincide.
        let salt = Data(repeating: 0x11, count: 32)
        let keys = try KeyDerivation.deriveKeys(password: Data("pw".utf8), salt: salt, parameters: .pbkdf2SHA512(iterations: 1_000))
        let encryption = keys.encryptionKey.withUnsafeBytes { Data($0) }
        let commitment = keys.commitmentKey.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(encryption, commitment)
    }

    func testDifferentSaltProducesDifferentKey() throws {
        let a = try KeyDerivation.deriveKeys(
            password: Data("pw".utf8),
            salt: Data(repeating: 0x01, count: 32),
            parameters: .pbkdf2SHA512(iterations: 1_000)
        )
        let b = try KeyDerivation.deriveKeys(
            password: Data("pw".utf8),
            salt: Data(repeating: 0x02, count: 32),
            parameters: .pbkdf2SHA512(iterations: 1_000)
        )
        XCTAssertNotEqual(
            a.encryptionKey.withUnsafeBytes { Data($0) },
            b.encryptionKey.withUnsafeBytes { Data($0) }
        )
    }

    func testEmptyPasswordIsRejected() {
        XCTAssertThrowsError(
            try KeyDerivation.deriveKeys(password: Data(), salt: Data(repeating: 0, count: 32), parameters: .pbkdf2SHA512(iterations: 1_000))
        ) { error in
            XCTAssertEqual(error as? CryptoError, .emptyPassword)
        }
    }

    // MARK: - Password normalisation

    func testPasswordIsNFCNormalised() throws {
        // "é" as a single code point vs "e" + combining acute.
        let composed = "caf\u{00E9}"
        let decomposed = "cafe\u{0301}"

        XCTAssertNotEqual(Array(composed.utf8), Array(decomposed.utf8))
        XCTAssertEqual(
            try KeyDerivation.normalisedPassword(composed),
            try KeyDerivation.normalisedPassword(decomposed)
        )
    }

    func testOverlongPasswordIsRejected() {
        let password = String(repeating: "a", count: EncryptionOptions.maximumPasswordByteCount + 1)
        XCTAssertThrowsError(try KeyDerivation.normalisedPassword(password)) { error in
            XCTAssertEqual(error as? CryptoError, .passwordTooLong(max: EncryptionOptions.maximumPasswordByteCount))
        }
    }

    // MARK: - Commitment

    func testCommitmentVerifiesAndRejectsTampering() throws {
        let keys = try KeyDerivation.deriveKeys(
            password: Data("pw".utf8),
            salt: Data(repeating: 0x07, count: 32),
            parameters: .pbkdf2SHA512(iterations: 1_000)
        )
        let prefix = Data(repeating: 0xAB, count: TestFormat.prefixSize)
        let commitment = KeyDerivation.commitment(for: prefix, key: keys.commitmentKey)

        XCTAssertTrue(KeyDerivation.isValidCommitment(commitment, prefix: prefix, key: keys.commitmentKey))
        XCTAssertFalse(
            KeyDerivation.isValidCommitment(commitment.flippedBit(at: 0), prefix: prefix, key: keys.commitmentKey)
        )
        XCTAssertFalse(
            KeyDerivation.isValidCommitment(commitment, prefix: prefix.flippedBit(at: 3), key: keys.commitmentKey)
        )
    }
}
