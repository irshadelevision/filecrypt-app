//
//  main.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import Darwin
import FileCryptCore
import Foundation
import Security

// MARK: - Tiny argument parser

struct Arguments {

    /// Options that are pure switches.
    private static let booleanOptions: Set<String> = [
        "quiet", "password-stdin", "help",
        "no-symbols", "allow-ambiguous", "no-required-classes"
    ]
    /// Options that always consume the following token as their value.
    private static let valueOptions: Set<String> = [
        "password", "password-env", "password-file",
        "memory", "time-cost", "parallelism", "chunk-size",
        "length", "count"
    ]

    private var flags: [String: String] = [:]
    private var switches: Set<String> = []
    private(set) var positional: [String] = []
    /// Long options that were given without the value they require.
    private(set) var missingValues: [String] = []

    init(_ raw: [String]) {
        var index = 0
        while index < raw.count {
            let token = raw[index]

            if token.hasPrefix("--") {
                let name = String(token.dropFirst(2))

                if let equals = name.firstIndex(of: "=") {
                    // `--option=value`
                    let key = String(name[name.startIndex..<equals])
                    let value = String(name[name.index(after: equals)...])
                    flags[key] = value
                } else if Arguments.booleanOptions.contains(name) {
                    // Must not swallow the next token: `--password-stdin in out`
                    // has two positional arguments after it, and treating `in`
                    // as the switch's value silently loses one of them.
                    switches.insert(name)
                } else if Arguments.valueOptions.contains(name) {
                    if index + 1 < raw.count {
                        flags[name] = raw[index + 1]
                        index += 1
                    } else {
                        missingValues.append(name)
                    }
                } else if index + 1 < raw.count, !raw[index + 1].hasPrefix("--") {
                    flags[name] = raw[index + 1]
                    index += 1
                } else {
                    switches.insert(name)
                }
            } else if token.hasPrefix("-"), token.count > 1 {
                switches.insert(String(token.dropFirst()))
            } else {
                positional.append(token)
            }

            index += 1
        }
    }

    func value(_ name: String) -> String? { flags[name] }
    func has(_ name: String) -> Bool { switches.contains(name) || flags[name] != nil }
}

// MARK: - Output helpers

func writeError(_ message: String) {
    FileHandle.standardError.write(Data(("fcrypt: " + message + "\n").utf8))
}

func writeInfo(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

/// One progress bar redrawn in place on stderr.
final class ProgressPrinter {
    private var lastPercent = -1
    private var enabled: Bool

    init(enabled: Bool) { self.enabled = enabled }

    func update(_ fraction: Double, phase: FileCipherPhase) {
        guard enabled else { return }
        let percent = Int((fraction * 100).rounded())
        guard percent != lastPercent else { return }
        lastPercent = percent
        let barWidth = 28
        let filled = Int((fraction * Double(barWidth)).rounded())
        let bar = String(repeating: "=", count: max(0, min(filled, barWidth)))
            + String(repeating: " ", count: max(0, barWidth - filled))
        FileHandle.standardError.write(Data("\r  [\(bar)] \(percent)%".utf8))
    }

    func finish() {
        guard enabled, lastPercent >= 0 else { return }
        FileHandle.standardError.write(Data("\r".utf8))
        FileHandle.standardError.write(Data(String(repeating: " ", count: 48).utf8))
        FileHandle.standardError.write(Data("\r".utf8))
    }
}

// MARK: - Secret input

/// Read a line from the terminal with echo disabled.
func readSecret(prompt: String) -> String? {
    FileHandle.standardError.write(Data(prompt.utf8))

    var original = termios()
    let isTTY = tcgetattr(STDIN_FILENO, &original) == 0
    if isTTY {
        var modified = original
        modified.c_lflag &= ~tcflag_t(ECHO)
        tcsetattr(STDIN_FILENO, TCSANOW, &modified)
    }

    defer {
        if isTTY {
            var restored = original
            tcsetattr(STDIN_FILENO, TCSANOW, &restored)
        }
        FileHandle.standardError.write(Data("\n".utf8))
    }

    return readLine(strippingNewline: true)
}

// MARK: - Usage

let usage = """
fcrypt — AES-256-GCM file encryption (Argon2id -> HKDF-SHA256)

USAGE:
  fcrypt encrypt <input> <output> [options]
  fcrypt decrypt <input> <output> [options]
  fcrypt info     <input>
  fcrypt generate [options]
  fcrypt selftest

OPTIONS:
  --password <pw>        Use this password (visible in the process list).
  --password-env <VAR>   Read the password from an environment variable.
  --password-file <path> Read the password from the first line of a file.
  --password-stdin       Read the password from the first line of stdin.
  --memory <kib>         Argon2id memory cost in KiB (default 65536 = 64 MiB).
  --time-cost <n>        Argon2id passes (default 3, max 64).
  --parallelism <n>      Argon2id lanes (default 1, max 16).
  --chunk-size <n>       Plaintext bytes per record (default 1048576).
  --quiet                Suppress progress output.

GENERATE OPTIONS:
  --length <n>           Characters to generate (default 20, 8..256).
  --count <n>            How many to print, one per line.
  --no-symbols           Letters and digits only.
  --allow-ambiguous      Keep look-alike characters (0/O/o, 1/l/I).
  --no-required-classes  Do not guarantee one character of every type.

KEY DERIVATION:
  New files use Argon2id. Memory is the parameter worth raising: it is what
  makes a guessing attack expensive on parallel hardware. Older PBKDF2 files
  are still read, and are re-encrypted with Argon2id when written again.

If none of the password options is given, fcrypt prompts on the terminal.
"""

/// Parse an integer option strictly.
///
/// If the user supplied a value we cannot understand, say so. Falling back to
/// the default would be the worst possible behaviour for a security tool:
/// `--memory 999999999999` would silently produce a file encrypted with the
/// *default* work factor while the user believed they had asked for more.
func strictUInt32(_ args: Arguments, _ name: String, default fallback: UInt32) -> UInt32? {
    guard let raw = args.value(name) else { return fallback }
    let trimmed = raw.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty, let value = UInt32(trimmed) else {
        writeError("--\(name) expects a whole number between 0 and \(UInt32.max); got \"\(raw)\".")
        return nil
    }
    return value
}

func strictInt(_ args: Arguments, _ name: String, default fallback: Int) -> Int? {
    guard let raw = args.value(name) else { return fallback }
    let trimmed = raw.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty, let value = Int(trimmed) else {
        writeError("--\(name) expects a whole number; got \"\(raw)\".")
        return nil
    }
    return value
}

// MARK: - Password resolution

func resolvePassword(args: Arguments, confirm: Bool) -> String? {
    if let value = args.value("password") {
        return value
    }
    if let variable = args.value("password-env") {
        guard let value = ProcessInfo.processInfo.environment[variable] else {
            writeError("environment variable \(variable) is not set.")
            return nil
        }
        return value
    }
    if let path = args.value("password-file") {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            writeError("could not read the password file at \(path).")
            return nil
        }
        return contents.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
    }
    if args.has("password-stdin") {
        return readLine(strippingNewline: true)
    }

    guard let first = readSecret(prompt: "Password: ") else {
        writeError("no password supplied.")
        return nil
    }
    if confirm {
        guard let second = readSecret(prompt: "Confirm password: ") else {
            writeError("no confirmation supplied.")
            return nil
        }
        guard first == second else {
            writeError("the passwords do not match.")
            return nil
        }
    }
    return first
}

// MARK: - Commands

func runTransform(mode: String, args: Arguments) -> Int32 {
    guard args.positional.count >= 2 else {
        writeError("\(mode) needs an input and an output path.")
        writeError("")
        FileHandle.standardError.write(Data(usage.utf8))
        return 2
    }

    let isEncrypt = (mode == "encrypt")
    let input = URL(fileURLWithPath: args.positional[0]).standardizedFileURL
    let output = URL(fileURLWithPath: args.positional[1]).standardizedFileURL

    guard let password = resolvePassword(args: args, confirm: isEncrypt) else { return 1 }
    guard !password.isEmpty else {
        writeError("the password is empty.")
        return 1
    }

    guard let memoryKiB = strictUInt32(args, "memory", default: EncryptionOptions.defaultMemoryKiB),
          let timeCost = strictUInt32(args, "time-cost", default: EncryptionOptions.defaultTimeCost),
          let parallelism = strictUInt32(args, "parallelism", default: EncryptionOptions.defaultParallelism),
          let chunkSize = strictInt(args, "chunk-size", default: EncryptionOptions.defaultChunkSize)
    else {
        return 2
    }
    let quiet = args.has("quiet")
    let printer = ProgressPrinter(enabled: !quiet)

    let progress: (Double) -> Void = { value in
        printer.update(value, phase: .processing)
    }

    do {
        if isEncrypt {
            try FileCipher.encryptFile(
                at: input,
                to: output,
                password: password,
                options: EncryptionOptions(
                    chunkSize: chunkSize,
                    memoryKiB: memoryKiB,
                    timeCost: timeCost,
                    parallelism: parallelism
                ),
                progress: progress
            )
        } else {
            try FileCipher.decryptFile(
                at: input,
                to: output,
                password: password,
                progress: progress
            )
        }
        printer.finish()
        if !quiet {
            writeInfo("\(isEncrypt ? "Encrypted" : "Decrypted") -> \(output.path)")
        }
        return 0
    } catch {
        printer.finish()
        let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        writeError(message)
        return 1
    }
}

func runGenerate(args: Arguments) -> Int32 {
    let quiet = args.has("quiet")

    guard let length = strictInt(args, "length", default: PasswordGenerator.defaultLength),
          let count = strictInt(args, "count", default: 1)
    else {
        return 2
    }
    guard count >= 1, count <= 1_000 else {
        writeError("--count must be between 1 and 1000.")
        return 2
    }

    let options = PasswordGeneratorOptions(
        length: length,
        includeLowercase: true,
        includeUppercase: true,
        includeDigits: true,
        includeSymbols: !args.has("no-symbols"),
        excludeAmbiguous: !args.has("allow-ambiguous"),
        requireEverySelectedClass: !args.has("no-required-classes")
    )

    do {
        if !quiet {
            // Goes to stderr so the passwords themselves stay pipeable.
            let summary = try PasswordGenerator.summary(options)
            writeInfo("# \(summary)")
        }
        for _ in 0..<count {
            print(try PasswordGenerator.generate(options))
        }
        return 0
    } catch {
        writeError((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        return 2
    }
}

func runInfo(args: Arguments) -> Int32 {
    guard let path = args.positional.first else {
        writeError("info needs a file path.")
        return 2
    }
    let url = URL(fileURLWithPath: path).standardizedFileURL

    do {
        let header = try FileCipher.readHeader(at: url)
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        print("file:            \(url.path)")
        print("container:       FileCrypt format \(header.format.rawValue)")
        print("cipher:          AES-256-GCM (chunked, per-record AAD binding)")
        print("key derivation:  \(header.keyDerivation.summary) -> HKDF-SHA256")
        if header.format == .pbkdf2SHA512 {
            print("note:            legacy format; re-encrypt to upgrade to Argon2id")
        }
        print("chunk size:      \(header.chunkSize) bytes")
        print("salt (hex):      \(header.salt.map { String(format: "%02x", $0) }.joined())")
        print("container size:  \(size) bytes")
        print("payload size:    \(max(0, size - header.encodedSize)) bytes")
        return 0
    } catch {
        let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        writeError(message)
        return 1
    }
}

func runSelfTest() -> Int32 {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("fcrypt-selftest-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }

    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    } catch {
        writeError("could not create a temporary directory: \(error.localizedDescription)")
        return 1
    }

    let sizes = [0, 1, 1023, 4096, 4097, 100_000, 1_048_576, 1_048_577]
    let password = "correct horse battery staple"

    do {
        for size in sizes {
            let plain = try SecureRandomBlob.make(count: size)
            let source = directory.appendingPathComponent("plain-\(size).bin")
            let container = directory.appendingPathComponent("plain-\(size).bin.fcrypt")
            let restored = directory.appendingPathComponent("plain-\(size).restored.bin")

            try plain.write(to: source)

            let options = EncryptionOptions(chunkSize: 4_096, memoryKiB: 1_024, timeCost: 1, parallelism: 1)
            try FileCipher.encryptFile(at: source, to: container, password: password, options: options)
            try FileCipher.decryptFile(at: container, to: restored, password: password)

            let recovered = try Data(contentsOf: restored)
            guard recovered == plain else {
                writeError("selftest FAILED at size \(size)")
                return 1
            }

            // A wrong password must be rejected.
            var rejected = false
            do {
                try FileCipher.decryptFile(
                    at: container,
                    to: directory.appendingPathComponent("bad.bin"),
                    password: password + "!"
                )
            } catch CryptoError.wrongPassword {
                rejected = true
            }
            guard rejected else {
                writeError("selftest FAILED: a wrong password was accepted at size \(size)")
                return 1
            }

            // A flipped ciphertext bit must be rejected.
            var tampered = try Data(contentsOf: container)
            tampered[tampered.count - 1] ^= 0x01
            let tamperedURL = directory.appendingPathComponent("tampered-\(size).fcrypt")
            try tampered.write(to: tamperedURL)

            var detected = false
            do {
                try FileCipher.decryptFile(
                    at: tamperedURL,
                    to: directory.appendingPathComponent("tampered.bin"),
                    password: password
                )
            } catch {
                detected = true
            }
            guard detected else {
                writeError("selftest FAILED: a corrupted container was accepted at size \(size)")
                return 1
            }

            writeInfo("  ok  \(size) bytes")
        }
    } catch {
        writeError("selftest FAILED: \((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)")
        return 1
    }

    writeInfo("selftest passed.")
    return 0
}

enum SecureRandomBlob {
    static func make(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == 0 else { throw CryptoError.randomGenerationFailed }
        return Data(bytes)
    }
}

// MARK: - Entry point

let rawArguments = Array(CommandLine.arguments.dropFirst())

guard let command = rawArguments.first, !command.hasPrefix("-") else {
    if rawArguments.contains("--help") || rawArguments.contains("-h") || rawArguments.isEmpty {
        FileHandle.standardError.write(Data(usage.utf8))
        exit(rawArguments.isEmpty ? 2 : 0)
    }
    writeError("unknown option. Run 'fcrypt --help'.")
    exit(2)
}

let arguments = Arguments(Array(rawArguments.dropFirst()))

if let missing = arguments.missingValues.first {
    writeError("option --\(missing) needs a value.")
    writeError("")
    FileHandle.standardError.write(Data(usage.utf8))
    exit(2)
}

let status: Int32

switch command {
case "encrypt", "decrypt":
    status = runTransform(mode: command, args: arguments)
case "info":
    status = runInfo(args: arguments)
case "generate":
    status = runGenerate(args: arguments)
case "selftest":
    status = runSelfTest()
case "help", "--help", "-h":
    FileHandle.standardError.write(Data(usage.utf8))
    status = 0
default:
    writeError("unknown command '\(command)'. Run 'fcrypt --help'.")
    status = 2
}

exit(status)
