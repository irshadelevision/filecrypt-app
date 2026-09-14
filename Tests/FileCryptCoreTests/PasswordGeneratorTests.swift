//
//  PasswordGeneratorTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation
import XCTest

@testable import FileCryptCore

final class PasswordGeneratorTests: XCTestCase {

    private let defaults = PasswordGeneratorOptions()

    // MARK: - Shape

    func testGeneratedPasswordHasTheRequestedLength() throws {
        for length in [8, 12, 20, 32, 64, 256] {
            var options = defaults
            options.length = length
            XCTAssertEqual(try PasswordGenerator.generate(options).count, length)
        }
    }

    func testGeneratedPasswordUsesOnlyTheSelectedClasses() throws {
        var options = PasswordGeneratorOptions(
            length: 64,
            includeLowercase: false,
            includeUppercase: false,
            includeDigits: true,
            includeSymbols: false
        )
        options.excludeAmbiguous = false

        let password = try PasswordGenerator.generate(options)
        XCTAssertTrue(password.allSatisfy(\.isNumber), "only digits were allowed: \(password)")

        options.includeDigits = false
        options.includeSymbols = true
        let symbols = try PasswordGenerator.generate(options)
        let allowed = Set(PasswordGenerator.alphabet(for: options))
        XCTAssertTrue(symbols.allSatisfy { allowed.contains($0) })
    }

    func testEverySelectedClassIsPresentWhenRequired() throws {
        // Smallest length, so the constraint is hardest to satisfy.
        var options = defaults
        options.length = PasswordGenerator.minimumLength
        options.requireEverySelectedClass = true

        for _ in 0..<200 {
            let password = try PasswordGenerator.generate(options)
            for characterClass in PasswordGenerator.characterClasses(for: options) {
                XCTAssertTrue(
                    password.contains { characterClass.contains($0) },
                    "\(password) is missing a character from one of the selected classes"
                )
            }
        }
    }

    func testAmbiguousCharactersAreExcludedByDefault() throws {
        var options = defaults
        options.length = 200
        options.excludeAmbiguous = true

        let ambiguous: Set<Character> = ["0", "O", "o", "1", "l", "I"]
        for _ in 0..<50 {
            let password = try PasswordGenerator.generate(options)
            XCTAssertFalse(
                password.contains { ambiguous.contains($0) },
                "\(password) contains a look-alike character"
            )
        }
    }

    func testAmbiguousCharactersAppearWhenExplicitlyAllowed() throws {
        var options = defaults
        options.length = 200
        options.excludeAmbiguous = false

        // With 200 characters from a pool containing six ambiguous ones, the
        // chance of none appearing is about 1e-6.
        let password = try PasswordGenerator.generate(options)
        XCTAssertTrue(password.contains { "0Oo1lI".contains($0) })
    }

    /// Pins the pool sizes. These are a specification, not an implementation
    /// detail: they are what the entropy figures in the README are derived
    /// from, so a change here must be a deliberate one.
    func testAlphabetSizeReflectsTheOptions() {
        // 24 lower + 24 upper + 8 digits + 24 symbols. The look-alike rule
        // removes o and l from lowercase, O and I from uppercase, and 0 and 1
        // from the digits.
        XCTAssertEqual(PasswordGenerator.alphabet(for: defaults).count, 80)

        var noSymbols = defaults
        noSymbols.includeSymbols = false
        XCTAssertEqual(PasswordGenerator.alphabet(for: noSymbols).count, 56)

        var ambiguousAllowed = noSymbols
        ambiguousAllowed.excludeAmbiguous = false
        XCTAssertEqual(PasswordGenerator.alphabet(for: ambiguousAllowed).count, 62)

        var everything = defaults
        everything.excludeAmbiguous = false
        XCTAssertEqual(PasswordGenerator.alphabet(for: everything).count, 86)

        var digitsOnly = defaults
        digitsOnly.includeLowercase = false
        digitsOnly.includeUppercase = false
        digitsOnly.includeSymbols = false
        XCTAssertEqual(PasswordGenerator.alphabet(for: digitsOnly).count, 8)
    }

    // MARK: - Randomness quality

    /// The point of rejection sampling.
    ///
    /// 62 divides 256 with remainder 8, so a naive `byte % 62` would make the
    /// first eight characters 5/4 as likely as the rest. Over 62,000 samples
    /// that is a ~3.5 % excess — far outside the noise this test allows.
    func testRandomIndexIsUniform() throws {
        let upperBound = 62
        let samples = 62_000
        let expected = Double(samples) / Double(upperBound)

        var counts = [Int](repeating: 0, count: upperBound)
        for _ in 0..<samples {
            counts[try PasswordGenerator.randomIndex(upperBound: upperBound)] += 1
        }

        XCTAssertEqual(counts.reduce(0, +), samples)

        // Chi-square with 61 degrees of freedom; 100 is far in the tail
        // (p ~ 0.002), so a fair generator essentially never trips it.
        let chiSquare = counts.reduce(0.0) { total, observed in
            let delta = Double(observed) - expected
            return total + delta * delta / expected
        }
        XCTAssertLessThan(
            chiSquare, 100,
            "distribution is not uniform (chi-square \(chiSquare))"
        )

        // No bucket may be wildly off on its own.
        for (index, observed) in counts.enumerated() {
            XCTAssertLessThan(
                abs(Double(observed) - expected) / expected, 0.25,
                "character \(index) appeared \(observed) times, expected about \(Int(expected))"
            )
        }
    }

    func testRandomIndexHandlesEdgeBounds() throws {
        // upperBound 1 must never loop or fail.
        for _ in 0..<100 {
            XCTAssertEqual(try PasswordGenerator.randomIndex(upperBound: 1), 0)
        }
        // A power of two leaves no remainder, so nothing is ever rejected.
        for _ in 0..<1000 {
            let index = try PasswordGenerator.randomIndex(upperBound: 256)
            XCTAssertTrue((0..<256).contains(index))
        }
    }

    func testRandomIndexRejectsImpossibleBounds() {
        XCTAssertThrowsError(try PasswordGenerator.randomIndex(upperBound: 0))
        XCTAssertThrowsError(try PasswordGenerator.randomIndex(upperBound: 257))
        XCTAssertThrowsError(try PasswordGenerator.randomIndex(upperBound: -1))
    }

    func testGeneratedPasswordsDoNotRepeat() throws {
        var options = defaults
        options.length = 24

        var seen = Set<String>()
        for _ in 0..<2_000 {
            XCTAssertTrue(
                seen.insert(try PasswordGenerator.generate(options)).inserted,
                "the generator produced a duplicate password"
            )
        }
    }

    // MARK: - Validation

    func testLengthBoundsAreEnforced() {
        var tooShort = defaults
        tooShort.length = PasswordGenerator.minimumLength - 1
        XCTAssertThrowsError(try PasswordGenerator.generate(tooShort))

        var tooLong = defaults
        tooLong.length = PasswordGenerator.maximumLength + 1
        XCTAssertThrowsError(try PasswordGenerator.generate(tooLong))
    }

    func testSelectingNoCharacterTypeIsRejected() {
        let empty = PasswordGeneratorOptions(
            includeLowercase: false,
            includeUppercase: false,
            includeDigits: false,
            includeSymbols: false
        )
        XCTAssertThrowsError(try PasswordGenerator.generate(empty)) { error in
            guard case CryptoError.invalidParameter = error else {
                return XCTFail("expected .invalidParameter, got \(error)")
            }
        }
        XCTAssertThrowsError(try PasswordGenerator.entropyBits(empty))
    }

    // MARK: - Entropy reporting

    func testEntropyMatchesTheAlphabetSize() throws {
        // 20 characters from a 62-character pool (no symbols, ambiguity allowed).
        var options = defaults
        options.includeSymbols = false
        options.excludeAmbiguous = false
        let bits = try PasswordGenerator.entropyBits(options)
        XCTAssertEqual(bits, 20 * log2(62), accuracy: 0.0001)
        XCTAssertGreaterThan(bits, 119)
    }

    func testTheDefaultSettingIsComfortablyStrong() throws {
        let bits = try PasswordGenerator.entropyBits(defaults)
        XCTAssertGreaterThan(
            bits, 120,
            "the default should be well beyond any feasible brute-force attack"
        )
    }

    func testSummaryReadsWell() throws {
        XCTAssertEqual(
            try PasswordGenerator.summary(PasswordGeneratorOptions(length: 20, includeSymbols: false, excludeAmbiguous: false)),
            "20 characters · about 119 bits"
        )
        var one = PasswordGeneratorOptions()
        one.length = 1
        XCTAssertTrue(try PasswordGenerator.summary(one).contains("1 character ·"))
    }

    // MARK: - Round trip through the real cipher

    func testAGeneratedPasswordActuallyEncryptsAndDecrypts() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PasswordGeneratorTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let plain = Data((0..<5_000).map { UInt8($0 % 251) })
        let source = directory.appendingPathComponent("plain.bin")
        let container = directory.appendingPathComponent("plain.bin.fcrypt")
        let restored = directory.appendingPathComponent("restored.bin")
        try plain.write(to: source)

        for _ in 0..<10 {
            let password = try PasswordGenerator.generate()
            let options = EncryptionOptions(
                chunkSize: 4_096,
                memoryKiB: 1_024,
                timeCost: 1,
                parallelism: 1
            )
            try FileCipher.encryptFile(at: source, to: container, password: password, options: options)
            try FileCipher.decryptFile(at: container, to: restored, password: password)
            XCTAssertEqual(try Data(contentsOf: restored), plain)
        }
    }
}
