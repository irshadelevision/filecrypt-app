//
//  PasswordStrength.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// A coarse, honest estimate of how hard a password would be to guess.
public enum PasswordStrength: Int, Comparable, Sendable {
    case veryWeak = 0
    case weak = 1
    case fair = 2
    case strong = 3
    case veryStrong = 4

    public static func < (lhs: PasswordStrength, rhs: PasswordStrength) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .veryWeak: return "Very weak"
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        case .veryStrong: return "Very strong"
        }
    }
}

/// The result of evaluating a password.
public struct PasswordAssessment: Equatable, Sendable {
    public let strength: PasswordStrength
    /// Estimated entropy in bits (already adjusted for obvious patterns).
    public let entropyBits: Double
    public let suggestions: [String]

    public init(strength: PasswordStrength, entropyBits: Double, suggestions: [String]) {
        self.strength = strength
        self.entropyBits = entropyBits
        self.suggestions = suggestions
    }
}

/// A deliberately simple estimator.
///
/// It estimates the size of the search space from the character classes used,
/// then discounts for the patterns attackers try first. It is a hint for the
/// user, not a security control: the actual protection is PBKDF2, and the app
/// never refuses a password the user insists on.
public enum PasswordStrengthEvaluator {

    public static func evaluate(_ password: String) -> PasswordAssessment {
        guard !password.isEmpty else {
            return PasswordAssessment(
                strength: .veryWeak,
                entropyBits: 0,
                suggestions: ["Enter a password."]
            )
        }

        let characters = Array(password)
        let length = characters.count

        var pool = 0
        if password.contains(where: { $0.isLowercase }) { pool += 26 }
        if password.contains(where: { $0.isUppercase }) { pool += 26 }
        if password.contains(where: { $0.isNumber }) { pool += 10 }
        if password.contains(where: { $0.isWhitespace }) { pool += 1 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { pool += 33 }
        // Non-ASCII characters come from a much larger alphabet.
        if password.contains(where: { !$0.isASCII }) { pool += 100 }
        pool = max(pool, 2)

        var entropy = Double(length) * log2(Double(pool))

        var suggestions: [String] = []

        let uniqueCount = Set(characters).count
        if uniqueCount <= 3 || Double(uniqueCount) <= Double(length) * 0.4 {
            entropy *= 0.55
            suggestions.append("Avoid repeating the same few characters.")
        }

        if hasRun(of: 3, in: characters, step: 1) || hasRun(of: 3, in: characters, step: -1) {
            entropy *= 0.8
            suggestions.append("Avoid sequences such as \"abcd\" or \"4321\".")
        }

        if containsKeyboardWalk(password) {
            entropy *= 0.8
            suggestions.append("Avoid keyboard patterns such as \"qwerty\".")
        }

        if let year = trailingYear(password) {
            entropy -= 6
            suggestions.append("Avoid years like \(year); they are guessed early.")
        }

        if commonPasswords.contains(password.lowercased()) {
            entropy = min(entropy, 12)
            suggestions.append("This is one of the most commonly used passwords.")
        }

        entropy = max(entropy, 0)

        if length < 12, entropy >= 50 {
            suggestions.append("Longer passwords are stronger than complicated ones.")
        }
        if suggestions.isEmpty, entropy < 80 {
            suggestions.append("Add a few more characters to make this much harder to crack.")
        }

        return PasswordAssessment(
            strength: strength(forEntropy: entropy),
            entropyBits: entropy,
            suggestions: Array(suggestions.prefix(2))
        )
    }

    private static func strength(forEntropy bits: Double) -> PasswordStrength {
        switch bits {
        case ..<36: return .veryWeak
        case ..<60: return .weak
        case ..<80: return .fair
        case ..<110: return .strong
        default: return .veryStrong
        }
    }

    private static func hasRun(of length: Int, in characters: [Character], step: Int) -> Bool {
        guard characters.count >= length else { return false }
        for start in 0...(characters.count - length) {
            var matched = true
            for offset in 0..<(length - 1) {
                let currentIndex = start + offset
                let nextIndex = start + offset + 1
                guard let a = characters[currentIndex].asciiValue,
                      let b = characters[nextIndex].asciiValue else {
                    matched = false
                    break
                }
                if Int(b) - Int(a) != step {
                    matched = false
                    break
                }
            }
            if matched { return true }
        }
        return false
    }

    private static let keyboardRows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"
    ]

    private static func containsKeyboardWalk(_ password: String) -> Bool {
        let lowered = password.lowercased()
        guard lowered.count >= 4 else { return false }
        for row in keyboardRows {
            let characters = Array(row)
            for start in 0...(characters.count - 4) {
                let segment = String(characters[start..<(start + 4)])
                if lowered.contains(segment) { return true }
            }
        }
        return false
    }

    private static func trailingYear(_ password: String) -> Int? {
        let digits = password.reversed().prefix { $0.isNumber }.reversed()
        guard digits.count == 4, let value = Int(String(digits)), (1900...2099).contains(value) else {
            return nil
        }
        return value
    }

    private static let commonPasswords: Set<String> = [
        "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
        "abc123", "letmein", "monkey", "dragon", "iloveyou", "admin", "welcome",
        "login", "passw0rd", "p@ssw0rd", "master", "sunshine", "princess",
        "football", "baseball", "superman", "trustno1", "hunter2", "shadow"
    ]
}
