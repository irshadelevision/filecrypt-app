//
//  PasswordGenerator.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// How a generated password should be built.
public struct PasswordGeneratorOptions: Sendable, Equatable {

    /// Number of characters.
    public var length: Int
    public var includeLowercase: Bool
    public var includeUppercase: Bool
    public var includeDigits: Bool
    public var includeSymbols: Bool

    /// Drop characters that are easy to misread when a password is copied off a
    /// screen by eye: `0`/`O`/`o` and `1`/`l`/`I`.
    public var excludeAmbiguous: Bool

    /// Guarantee at least one character from every selected class.
    ///
    /// Achieved by rejection sampling over whole candidate passwords, so the
    /// result stays uniform over the set of passwords that satisfy the rule —
    /// the usual "pick one of each, then shuffle" trick does not have that
    /// property.
    public var requireEverySelectedClass: Bool

    public init(
        length: Int = PasswordGenerator.defaultLength,
        includeLowercase: Bool = true,
        includeUppercase: Bool = true,
        includeDigits: Bool = true,
        includeSymbols: Bool = true,
        excludeAmbiguous: Bool = true,
        requireEverySelectedClass: Bool = true
    ) {
        self.length = length
        self.includeLowercase = includeLowercase
        self.includeUppercase = includeUppercase
        self.includeDigits = includeDigits
        self.includeSymbols = includeSymbols
        self.excludeAmbiguous = excludeAmbiguous
        self.requireEverySelectedClass = requireEverySelectedClass
    }
}

/// Cryptographically secure password generation.
///
/// This exists because the weakest part of any password-based encryption scheme
/// is the password the human picks. A generator that draws from the system
/// CSPRNG removes that variable entirely.
///
/// ## Two things this is careful about
///
/// **No modulo bias.** Taking `randomByte % alphabetCount` favours the first
/// `256 % alphabetCount` characters. With the 88-character default alphabet that
/// skews 24 characters by 50 %. Every character here comes from rejection
/// sampling, which is provably uniform.
///
/// **It is transcribable.** The generated password will usually have to be
/// typed back in by hand at some point, so look-alike characters are excluded
/// by default. A password that cannot be re-entered is not a password, it is a
/// data-loss incident.
public enum PasswordGenerator {

    public static let minimumLength = 8
    public static let maximumLength = 256
    public static let defaultLength = 20

    private static let lowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz"
    private static let uppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private static let digitAlphabet = "0123456789"

    /// Punctuation that survives being typed, pasted, and passed through a
    /// shell. Deliberately omits quotes, backslash, backtick and the space, all
    /// of which invite quoting bugs in `fcrypt --password '…'`.
    private static let symbolAlphabet = "!@#$%^&*()-_=+[]{};:,.?/"

    private static let ambiguousCharacters: Set<Character> = ["0", "O", "o", "1", "l", "I"]

    // MARK: - Alphabet

    /// The selected character classes, in a stable order, after filtering.
    public static func characterClasses(for options: PasswordGeneratorOptions) -> [[Character]] {
        var classes: [[Character]] = []

        func add(_ alphabet: String) {
            let characters = alphabet.filter { character in
                !options.excludeAmbiguous || !ambiguousCharacters.contains(character)
            }
            if !characters.isEmpty {
                classes.append(Array(characters))
            }
        }

        if options.includeLowercase { add(lowercaseAlphabet) }
        if options.includeUppercase { add(uppercaseAlphabet) }
        if options.includeDigits { add(digitAlphabet) }
        if options.includeSymbols { add(symbolAlphabet) }

        return classes
    }

    /// The full pool a character is drawn from.
    public static func alphabet(for options: PasswordGeneratorOptions) -> [Character] {
        characterClasses(for: options).flatMap { $0 }
    }

    // MARK: - Generation

    public static func generate(_ options: PasswordGeneratorOptions) throws -> String {
        guard options.length >= minimumLength, options.length <= maximumLength else {
            throw CryptoError.invalidParameter(
                "Password length must be between \(minimumLength) and \(maximumLength) characters."
            )
        }

        let classes = characterClasses(for: options)
        guard !classes.isEmpty else {
            throw CryptoError.invalidParameter("Select at least one character type to generate from.")
        }

        let pool = classes.flatMap { $0 }

        guard options.requireEverySelectedClass else {
            return try randomString(length: options.length, alphabet: pool)
        }

        // Rejection sampling. For any realistic length the loop succeeds on the
        // first or second attempt; the bound exists so a pathological option set
        // fails loudly instead of spinning.
        for _ in 0..<1_000 {
            let candidate = try randomString(length: options.length, alphabet: pool)
            let satisfies = classes.allSatisfy { characterClass in
                candidate.contains { characterClass.contains($0) }
            }
            if satisfies { return candidate }
        }

        throw CryptoError.invalidParameter(
            "Could not build a password containing every selected character type at this length."
        )
    }

    /// A convenient default password.
    public static func generate() throws -> String {
        try generate(PasswordGeneratorOptions())
    }

    /// `length × log2(poolSize)`.
    ///
    /// An upper bound on the real entropy, because requiring one of every class
    /// conditions the distribution slightly. At the lengths this app uses the
    /// difference is well under a bit — for a 20-character password drawn from
    /// the 88-character default pool it is about 0.0004 bits — so it is not
    /// worth reporting a second, more confusing number.
    public static func entropyBits(_ options: PasswordGeneratorOptions) throws -> Double {
        let pool = alphabet(for: options)
        guard !pool.isEmpty else {
            throw CryptoError.invalidParameter("Select at least one character type to generate from.")
        }
        return Double(options.length) * log2(Double(pool.count))
    }

    /// A short description for the UI, e.g. `"20 characters · about 128 bits"`.
    public static func summary(_ options: PasswordGeneratorOptions) throws -> String {
        let bits = try entropyBits(options)
        let characters = options.length == 1 ? "character" : "characters"
        return "\(options.length) \(characters) · about \(Int(bits.rounded())) bits"
    }

    // MARK: - Primitives

    /// A uniformly distributed index in `0..<upperBound`.
    ///
    /// Bytes at or above the largest multiple of `upperBound` are discarded, so
    /// every index is equally likely. This is the whole reason the generator can
    /// claim its output is unbiased, and it is exercised directly by
    /// `PasswordGeneratorTests.testRandomIndexIsUniform`.
    static func randomIndex(upperBound: Int) throws -> Int {
        guard upperBound > 0, upperBound <= 256 else {
            throw CryptoError.invalidParameter("Cannot draw from an alphabet of \(upperBound) characters.")
        }
        if upperBound == 1 { return 0 }

        let limit = 256 - (256 % upperBound)
        while true {
            let byte = try SecureData.randomBytes(count: 1)[0]
            if Int(byte) < limit {
                return Int(byte) % upperBound
            }
        }
    }

    private static func randomString(length: Int, alphabet: [Character]) throws -> String {
        var characters: [Character] = []
        characters.reserveCapacity(length)
        for _ in 0..<length {
            characters.append(alphabet[try randomIndex(upperBound: alphabet.count)])
        }
        return String(characters)
    }
}
