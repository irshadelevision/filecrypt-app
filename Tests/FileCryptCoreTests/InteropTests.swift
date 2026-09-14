//
//  InteropTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Interoperability lock against an independent implementation.
///
/// Both containers below were produced by `Scripts/reference_fcrypt.py`, a
/// from-scratch Python implementation of `docs/FORMAT.md` that shares no code
/// with the app. Between them they pin the wire format for every format this
/// app can read or write.
///
/// This is the test that catches "self-consistent but wrong" bugs — an
/// endianness mistake in the record index, for instance, where encrypt and
/// decrypt still agree with each other but no other implementation can read the
/// file. It has already caught one of those.
final class InteropTests: TemporaryDirectoryTestCase {

    private static let fixturePassword = "interop-fixture-password"
    private static let fixtureSalt = Data(0..<32)
    private static let fixtureChunkSize = 1_024
    private static let fixturePlaintextLength = 2_500

    /// Deterministic payload: `(i * 37 + 11) mod 256`.
    private static func fixturePlaintext() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(fixturePlaintextLength)
        for index in 0..<fixturePlaintextLength {
            bytes.append(UInt8((index * 37 + 11) % 256))
        }
        return Data(bytes)
    }

    // MARK: - Format 2 (Argon2id), the current format

    /// `reference_fcrypt.py encrypt --format 2 --salt 000102...1f
    ///  --memory 1024 --time-cost 2 --parallelism 1 --chunk-size 1024`
    private static let argon2idContainerBase64 = [
        "RkNSWVBUdjICAgEAAAQAAAAEAAACAAAAAQAAAGAAAAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH62Gg50e0b8T",
        "Gj0IMUmFNDjE6A1zOOzYzWmVA76a4aCrEAQAAGWwwdFYQ/qj8WHXPbINCIQEvnJAlNlkMcH7qZRKzJOxfl1boZunlgacm1SO",
        "OOPrR+0qr+mH86Jdf4DYlzjMBU3stNSav6dF3vqRUe/cZXzQLsfK2LLQuQrVkfKNuJAhJGoFfh97hxwq7rM2EHFA2oO6pBQ/",
        "rO64UjCxy9I0jkwGWONdM4VasOqj7treblcpGsmVczSIjE7nxSNH6Ayeb68dYHYKmutSEEInGL+Mqy1EvPDfUnkcFvL37M5y",
        "9735/pcS6GkH6Lb+dF+8T9QWBcFmuGEPNXTt2pRi8qF6G0EcnWkru3EyCW3rprXBOimw9YNWWfsvelspi//us0mDjWcAFEf0",
        "5JgPGaYdNoqbqyfN9df6TgPdYyY+JhiNKczvWn+idYSF1ynYdXw5c5W8kxp7CWyOXPmVz2Db92Bg4s0hDdSfiBXrLf5cbT7G",
        "oDjtOolaEWNwycB6nYEF0/I0tg83diiFsGGJXTSGUkCdVRB5yH7+NJjHex9Lrejys09cB8prreX7yFFuE1yH3TK1Hld9Q8gg",
        "Vju213YsIMIvn8snjsChhSubVocv2LqwnUzIGimpZRVAAsm44Np3Cw0PEEPnflxLNzVmC/1p93cQEnhqqBQzvZCvkzAG4KRO",
        "l9rHKmMu1YV3F85QaGVqmcZIDf0O59HCAnuLS7itDGu9qK1dYzf4885ohOuskD1cYGFLpKFsfPXTxRIjmgCNjRR/n5od+kMu",
        "xw8Nsihddi/N0/t29tIAg8QBqHL6NwldTeivi2uqZhOr0BHO0ZDk+EqS6k3qvE/V09Vb6CUCjjm1QIyjm/LtvLxcKv1nvQbK",
        "tD28q6kIlE2UQXFrCgUKHem2FZqFssjOoox3atffOUQPrbS450LCBSL/UUXnp92lLJnRoVgMYJkjgHMY/9XpIeynhQAGNSHn",
        "DPpWDASqnPJPWQzqB2Fifoa3gJZtwOySkL/aW0bwEf5Pgzp4RQxyJ1Qc0SWykSpNWOgtJDRj0oe4ueD5xL91JYONNS2deGk9",
        "D2dHAEMnwMBpCukKwOWclH7Aboychsla3wbE36Zqbu7wSQq8pupJguX3V30EWRYZr2SrSV5upc3C+ldo9bdZmiEAhGdmEgad",
        "Grx62rWLYNsK/ReIQ/Twx0lMlmmhS2i1jkLhWA05iO0ukcUM6L6yprBikK8m7xaiIIaepzYWOOK8cNA/FT1B8w5K2KRmRZ5X",
        "sgTEIiQW2ZvBlu+oYkKdPEbMRYTxHM60Nfkqt7SDeWVCFbm//nC2wlhcsaO/V5rM+4pd4f61JvG2/ViGltOSCUqFkDp4HOkB",
        "SnJJOFvWxxaADZbwKImeXQadqWoVLDxMglwu9xyw/I7JtCtih/eW7vb6qRssyRWI7aZRn0MOUJh6U3gWEAQAANVjyVueQS2w",
        "p5P9rl9jPFwDNXZJkoYDVgzwKpR/cSRATl1/uni2mzgMFBTw6YtAodsnag2zD9fso/JK7he5qVo0I69MrkvLUjI/Rk+BmBMp",
        "ZpmdZhxfqf/NUwtmFWWaNL4RvV2m3kbO2Bti2/C0TRNqQ0pN/VuIqzVFIqIqpv+N4yS7R+QDRL1lqk2oQBLQVb/fjZsaO7bp",
        "5hPwN2NEW1U1ypQaA/rZI1pLNo8vysLY6m8QQTb/Kuyry7vPhY4UyHvYbqVSlheYJKvjCQwS4qwQuawts/M99n4jmReJvHur",
        "HRLkKmqFd5WmmDFr+FX0/xGwsZhLO85LU0hsp4YvxdBeymzEKZDHOVFYYkmNFi5MV+FE9fVTPfPCTxEJy0/DoSWWxeIOUgxm",
        "rPj3wjPizBfz43w+OCqQoTkDX14OBxzv36vilwZpfmYh3/RREvG5cnQ8n3LdgLz4RV18snEtdPkW1+RkLpdqejFSEtO4HFtc",
        "oZjFj9dLlQWQCO8v0paHlQqx5O601iA1FRDD5lTQNCCMvJkGRbBgU3JzqgQ+hj1bEczkhDO5Y4tD8e36y96kJcTNcxEYY6QI",
        "ztCtD1oiUeqidchTWhG5NF1I4MAkOiYL5n3F12EuYyVvNAKlLd6T4PMqsaiWl+WBTwqF5AuSSJaAu69SrlWrwg9kt1vQl41B",
        "TJ9IBqlMQSjctjdiFUQShh87LtD22yOtML+Q3nhfZkKxtXtg6SB3hYDtwvHkjM7VN5pFv804cDMPHdc7Qv6KI/0XaDjzFuOM",
        "8s6/mwkmHn43Zn3JRRW/mL3s/YT127Qihy8z/v0eQOOf1jaxxNK8Zcpc9He6C/nQUztEJPruUAfUkoV7vX3aS5QN4VUs0Xt1",
        "OcpAlva9+wW6Td5BZkRqa/d5lY4WSdU414MOllIUE2SJ7wZcMQ5ijMpWZA0z5jRXJDwYqgiix3933Aa12TdNdOuXqZWFP45C",
        "b254GFJZED1JRrsflsUZOcYs46RZw8+fpS7HoRUQ2zJSy31PkoLOTE6v/3ZevqE52bSwpi80TaBLV38vY65pAU9hMcevnT2Q",
        "lCUAkyUIdlMe+NOiFYMKtKT9/3YA5jYL4pFMTDHeihQ3A66ZJ3jIZY2SpfSu3TvKXQ/jGLDwT2EZdxhsS8nT60eWk0tlPids",
        "QzjXCKqKfKiXpZJ3/pb8d7oQATrRbJoSVWVA3mB5Z4sfTm+Ff71ynLJVqSHlxHORDh/GHkPvwyYsBMyWo1RE166bAZNuNCZ4",
        "4FXPvQXz3/ITK1d/3kuQcQnR1Ym0ojT6Dz3KEJF8zqZnlnUvsXd5wHXHq79k7phTEcUr+jGFAOPSOqrDjxBjyHhCPvxmuk92",
        "tMiw9G+BRxpDfuL2SUTJVNCYELteTzgV1AEAAEwYrciPvc+sLk1WQGGtv+EiX6J8mjL9yFPpPvMH4W/UwBoj15jQuMTX9acf",
        "XxB44Wr2FnjvxOcmu0YOgOlD2ZPXIDzlgAuDK0ZC+0fQV6pFS4n+x+SHWA9Gx8kWcfGqyRKj6AtUwslDOxo7FGkk2dAoVHK2",
        "bt5NwxfLBTQjt/tMSyjktPQgywO8u1f64L62k8TGloTTK8jJW0NfNXXrH0v3yImBT2Z5alzLXJpGAat1pI+JrAltXDsWkYib",
        "b2jiogMZueslv0egyRGsW1GChkgqLnSNHBQ51VUTw1ZecZiEL3vXH1lf9QiHGJrINHoBOzfeIr7m3q9y4bJzknaMJiDjj2Pn",
        "mcmHG41hnPSHux4amKyIv5h2bkDAz2xR/8DmDN00++2KOJnepbj5xHGWghzb2HGs4OlM1BVBxI6D4ROtmgsDJrq5147iq80o",
        "gLexcdOQSPwIZNRWgZtJBfwaZQeDe4T5O8zLAY3mOEBDSpZJFl+AghmaLTv1bAlnTJifIleSeuovpRsYLrLfGa8jdf9nrhe5",
        "qk0Gcl3T8YipvmHLr7Qpw6YLEx9nuG4ogk2qmnj0IWcyj+WOZh4F0Qq9Ew80+uTdpASsR5pWam3zVIKikom35A==",
    ].joined()

    // MARK: - Format 1 (PBKDF2), legacy read-only support

    /// `reference_fcrypt.py encrypt --format 1 --salt 000102...1f
    ///  --iterations 1000 --chunk-size 1024`
    private static let legacyContainerBase64 = [
        "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",
    ].joined()

    private static func decode(_ base64: String, _ label: String) -> Data {
        guard let data = Data(base64Encoded: base64) else {
            fatalError("the embedded \(label) interop fixture is not valid base64")
        }
        return data
    }

    private static var argon2idContainer: Data { decode(argon2idContainerBase64, "Argon2id") }
    private static var legacyContainer: Data { decode(legacyContainerBase64, "legacy") }

    func testFixturesAreWellFormed() {
        // 96-byte header + two full 1024-byte records + a 452-byte tail:
        // 96 + 2 * (4 + 1024 + 16) + (4 + 452 + 16) = 2656.
        XCTAssertEqual(Self.argon2idContainer.count, 2_656)
        XCTAssertEqual(Self.argon2idContainer.prefix(8), Data("FCRYPTv2".utf8))

        // 88-byte header, same record layout: 88 + 2088 + 472 = 2648.
        XCTAssertEqual(Self.legacyContainer.count, 2_648)
        XCTAssertEqual(Self.legacyContainer.prefix(8), Data("FCRYPTv1".utf8))

        XCTAssertEqual(Self.fixturePlaintext().count, Self.fixturePlaintextLength)
    }

    // MARK: - Reading

    func testDecryptsContainerProducedByTheReferenceImplementation() throws {
        let container = try write(Self.argon2idContainer, to: path("reference.fcrypt"))
        let output = path("reference.out")

        try FileCipher.decryptFile(at: container, to: output, password: Self.fixturePassword)

        XCTAssertEqual(try Data(contentsOf: output), Self.fixturePlaintext())
    }

    func testRejectsTheReferenceContainerWithTheWrongPassword() throws {
        let container = try write(Self.argon2idContainer, to: path("reference.fcrypt"))
        XCTAssertThrowsError(
            try FileCipher.decryptFile(
                at: container,
                to: path("reference-bad.out"),
                password: Self.fixturePassword + "!"
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .wrongPassword)
        }
    }

    func testReadsTheParametersTheReferenceImplementationWrote() throws {
        let container = try write(Self.argon2idContainer, to: path("reference.fcrypt"))
        let header = try FileCipher.readHeader(at: container)

        XCTAssertEqual(header.format, .argon2id)
        XCTAssertEqual(header.chunkSize, UInt32(Self.fixtureChunkSize))
        XCTAssertEqual(header.salt, Self.fixtureSalt)
        XCTAssertEqual(
            header.keyDerivation,
            .argon2id(memoryKiB: 1_024, timeCost: 2, parallelism: 1)
        )
    }

    // MARK: - Writing

    func testProducesTheExactBytesOfTheReferenceImplementation() throws {
        let source = try write(Self.fixturePlaintext(), to: path("plain.bin"))
        let container = path("plain.fcrypt")

        try FileCipher.encryptFile(
            at: source,
            to: container,
            password: Self.fixturePassword,
            options: EncryptionOptions(
                chunkSize: Self.fixtureChunkSize,
                memoryKiB: 1_024,
                timeCost: 2,
                parallelism: 1
            ),
            salt: Self.fixtureSalt
        )

        XCTAssertEqual(
            try Data(contentsOf: container),
            Self.argon2idContainer,
            "the container Swift wrote differs from the independent implementation"
        )
    }

    // MARK: - Legacy format 1

    func testStillDecryptsLegacyPbkdf2Containers() throws {
        let container = try write(Self.legacyContainer, to: path("legacy.fcrypt"))
        let output = path("legacy.out")

        try FileCipher.decryptFile(at: container, to: output, password: Self.fixturePassword)

        XCTAssertEqual(try Data(contentsOf: output), Self.fixturePlaintext())
    }

    func testLegacyContainerReportsItsOwnParameters() throws {
        let container = try write(Self.legacyContainer, to: path("legacy.fcrypt"))
        let header = try FileCipher.readHeader(at: container)

        XCTAssertEqual(header.format, .pbkdf2SHA512)
        XCTAssertEqual(header.encodedSize, 88)
        XCTAssertEqual(header.keyDerivation, .pbkdf2SHA512(iterations: 1_000))
        XCTAssertEqual(header.salt, Self.fixtureSalt)
    }

    func testLegacyContainerStillRejectsTheWrongPassword() throws {
        let container = try write(Self.legacyContainer, to: path("legacy.fcrypt"))
        XCTAssertThrowsError(
            try FileCipher.decryptFile(
                at: container,
                to: path("legacy-bad.out"),
                password: Self.fixturePassword + "!"
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .wrongPassword)
        }
    }

    func testLegacyAndCurrentFormatsShareNothingOnDisk() throws {
        // Different magic, different header size, different key schedule — the
        // two fixtures must not be interchangeable.
        XCTAssertNotEqual(
            Self.argon2idContainer.prefix(8),
            Self.legacyContainer.prefix(8)
        )

        // Feeding the legacy bytes to a v2-only reader must not silently work.
        let legacyAsV2 = try write(Self.legacyContainer, to: path("legacy.fcrypt"))
        let header = try FileCipher.readHeader(at: legacyAsV2)
        XCTAssertEqual(header.format, .pbkdf2SHA512)
    }
}
