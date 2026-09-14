//
//  Argon2Tests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

/// Known-answer tests for Argon2id.
///
/// Every expected value below was produced by the *reference* command-line
/// tool (Homebrew's `argon2`, which is phc-winner-argon2 at tag 20190702):
///
///     printf 'password' | argon2 somesalt -id -t 2 -m 16 -p 1 -l 32 -r
///
/// These catch the two failure modes that matter for a vendored C dependency:
/// the source was not copied faithfully, and the Swift marshalling layer
/// passes its arguments in the wrong order or with the wrong widths. The
/// algorithm itself is the reference implementation, so it is not re-derived
/// here.
final class Argon2Tests: XCTestCase {

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func derive(
        _ password: String,
        salt: String,
        timeCost: UInt32,
        memoryKiB: UInt32,
        parallelism: UInt32,
        length: Int = 32
    ) throws -> String {
        hex(
            try Argon2.deriveKey(
                password: Data(password.utf8),
                salt: Data(salt.utf8),
                memoryKiB: memoryKiB,
                timeCost: timeCost,
                parallelism: parallelism,
                outputByteCount: length
            )
        )
    }

    // MARK: - Reference vectors

    func testArgon2idMatchesReferenceVectors() throws {
        let vectors: [(password: String, salt: String, t: UInt32, m: UInt32, p: UInt32, length: Int, expected: String)] = [
            (
                "password", "somesalt", 2, 65_536, 1, 32,
                "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
            ),
            (
                "password", "somesalt", 3, 4_096, 4, 32,
                "a6813fd21d9c8dbbfe5253c381154e1eac25982018a392c5e6578caef42a56b2"
            ),
            (
                "password", "somesalt", 1, 256, 1, 32,
                "024ec0c1ac65d08d95f1e46fcc33801dc5dcee045470e74765b7f7381b50ecd5"
            ),
            (
                "password", "somesalt", 2, 1_024, 2, 64,
                "96e0432edcab74093a934b0541c79c0ff4bd2f4c15380c453b1088756ef725c6"
                    + "2dc45fd2747db3afa5b80e6faea506e567f64dc2830a116c7a956d0c09a203c3"
            ),
            (
                "pass wörd🔐", "saltsalt", 2, 1_024, 1, 32,
                "7dd50e1aeea883a2e3170e6a2529dffca68b9d9aabdcd346192e25b2b86ce59a"
            ),
            (
                "password", "0123456789abcdef0123456789abcdef", 2, 1_024, 1, 32,
                "480054b71a15660eac2b8e0e5824628f6048d8c075fc48895e75f7dd0df4b91d"
            )
        ]

        for vector in vectors {
            XCTAssertEqual(
                try derive(
                    vector.password,
                    salt: vector.salt,
                    timeCost: vector.t,
                    memoryKiB: vector.m,
                    parallelism: vector.p,
                    length: vector.length
                ),
                vector.expected,
                "Argon2id mismatch for t=\(vector.t) m=\(vector.m) p=\(vector.p) l=\(vector.length)"
            )
        }
    }

    // MARK: - Behaviour

    func testOutputIsDeterministicAndSensitiveToEveryInput() throws {
        let baseline = try derive("password", salt: "somesalt", timeCost: 2, memoryKiB: 512, parallelism: 1)

        // Same inputs, same output.
        XCTAssertEqual(
            baseline,
            try derive("password", salt: "somesalt", timeCost: 2, memoryKiB: 512, parallelism: 1)
        )

        // Every parameter must matter.
        XCTAssertNotEqual(baseline, try derive("passwore", salt: "somesalt", timeCost: 2, memoryKiB: 512, parallelism: 1))
        XCTAssertNotEqual(baseline, try derive("password", salt: "somesalu", timeCost: 2, memoryKiB: 512, parallelism: 1))
        XCTAssertNotEqual(baseline, try derive("password", salt: "somesalt", timeCost: 3, memoryKiB: 512, parallelism: 1))
        XCTAssertNotEqual(baseline, try derive("password", salt: "somesalt", timeCost: 2, memoryKiB: 1_024, parallelism: 1))
    }

    func testMemoryCostActuallyChangesTheCost() throws {
        // A 4 MiB run must take meaningfully longer than a 32 KiB run. This is
        // the whole point of choosing a memory-hard function, so it is worth
        // asserting rather than assuming.
        func time(memoryKiB: UInt32) throws -> Double {
            let start = CFAbsoluteTimeGetCurrent()
            _ = try Argon2.deriveKey(
                password: Data("password".utf8),
                salt: Data("somesalt".utf8),
                memoryKiB: memoryKiB,
                timeCost: 3,
                parallelism: 1,
                outputByteCount: 32
            )
            return CFAbsoluteTimeGetCurrent() - start
        }

        let cheap = try time(memoryKiB: 32)
        let expensive = try time(memoryKiB: 4 * 1_024)
        XCTAssertGreaterThan(
            expensive,
            cheap * 5,
            "a 128x larger memory cost should dominate the runtime (cheap=\(cheap)s expensive=\(expensive)s)"
        )
    }

    // MARK: - Parameter validation

    func testParameterBoundsAreEnforcedBeforeRunning() {
        func expectInvalid(
            memoryKiB: UInt32 = 1_024,
            timeCost: UInt32 = 2,
            parallelism: UInt32 = 1,
            salt: String = "somesalt",
            password: String = "password",
            _ message: String
        ) {
            XCTAssertThrowsError(
                try Argon2.deriveKey(
                    password: Data(password.utf8),
                    salt: Data(salt.utf8),
                    memoryKiB: memoryKiB,
                    timeCost: timeCost,
                    parallelism: parallelism,
                    outputByteCount: 32
                ),
                message
            )
        }

        expectInvalid(password: "", "an empty password must be refused")
        expectInvalid(salt: "", "an empty salt must be refused")
        expectInvalid(memoryKiB: 4, "memory below the minimum must be refused")
        expectInvalid(memoryKiB: Argon2.maximumMemoryKiB + 1, "absurd memory must be refused before allocating")
        expectInvalid(timeCost: 0, "a zero time cost must be refused")
        expectInvalid(timeCost: Argon2.maximumTimeCost + 1, "an absurd time cost must be refused")
        expectInvalid(parallelism: 0, "zero parallelism must be refused")
        expectInvalid(parallelism: Argon2.maximumParallelism + 1, "absurd parallelism must be refused")
        expectInvalid(memoryKiB: 64, parallelism: 16, "memory below 8 KiB per lane must be refused")
    }

    func testMemorySufficiencyRuleMatchesTheSpecification() {
        // Argon2 requires m >= 8 * p.
        XCTAssertTrue(Argon2.isMemorySufficient(memoryKiB: 8, parallelism: 1))
        XCTAssertTrue(Argon2.isMemorySufficient(memoryKiB: 128, parallelism: 16))
        XCTAssertFalse(Argon2.isMemorySufficient(memoryKiB: 127, parallelism: 16))
        XCTAssertFalse(Argon2.isMemorySufficient(memoryKiB: 8, parallelism: 2))
    }

    func testAllSupportedParallelismValuesProduceDistinctKeys() throws {
        var seen: Set<String> = []
        for parallelism: UInt32 in 1...4 {
            let key = try derive(
                "password",
                salt: "somesalt",
                timeCost: 2,
                memoryKiB: 256,
                parallelism: parallelism
            )
            XCTAssertEqual(key.count, 64, "32 bytes as hex")
            XCTAssertTrue(seen.insert(key).inserted, "parallelism \(parallelism) collided with another lane count")
        }
    }
}
