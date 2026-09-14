//
//  AppModel.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import AppKit
import Combine
import FileCryptCore
import Foundation

/// Everything the window needs to know.
///
/// `@MainActor` on the whole class means all published state is only ever
/// mutated on the main thread; the crypto itself runs on a worker queue.
@MainActor
final class AppModel: ObservableObject {

    enum Mode: String, CaseIterable, Identifiable {
        case encrypt
        case decrypt

        var id: String { rawValue }

        var title: String {
            switch self {
            case .encrypt: return "Encrypt"
            case .decrypt: return "Decrypt"
            }
        }

        var actionTitle: String {
            switch self {
            case .encrypt: return "Encrypt File"
            case .decrypt: return "Decrypt File"
            }
        }

        var symbolName: String {
            switch self {
            case .encrypt: return "lock.fill"
            case .decrypt: return "lock.open.fill"
            }
        }

        var workingVerb: String {
            switch self {
            case .encrypt: return "Encrypting"
            case .decrypt: return "Decrypting"
            }
        }
    }

    // MARK: - Published state

    @Published var mode: Mode = .encrypt {
        didSet {
            guard oldValue != mode else { return }
            refreshDestination()
            successMessage = nil
            errorMessage = nil
        }
    }

    @Published private(set) var inputURL: URL?
    @Published private(set) var destinationURL: URL?
    @Published private(set) var inputDetail: String?
    /// `true` when the selected file starts with the FileCrypt magic.
    @Published private(set) var inputLooksEncrypted = false
    /// `true` when the selection is a folder rather than a file.
    @Published private(set) var inputIsDirectory = false
    /// `true` when the selected container holds an archived folder.
    @Published private(set) var containerHoldsDirectory = false

    @Published var password = "" {
        didSet {
            guard oldValue != password else { return }
            passwordAssessment = PasswordStrengthEvaluator.evaluate(password)
            // Typing over a generated password must not leave the "generated"
            // banner claiming otherwise.
            if password != generatedPasswordValue { generatedPasswordSummary = nil }
            generatedPasswordValue = password
        }
    }
    @Published var confirmPassword = ""
    @Published var revealPassword = false
    @Published var keyStrength: KeyStrengthPreset = .standard

    // Password generator settings. Kept on the model so the choices survive
    // from one file to the next.
    @Published var generatorLength = PasswordGenerator.defaultLength
    @Published var generatorIncludeSymbols = true
    @Published var generatorExcludeAmbiguous = true
    @Published var generatorRequireEveryClass = true
    /// Set after generating, so the UI can tell the user what they just got and
    /// that it will not be shown again.
    @Published private(set) var generatedPasswordSummary: String?

    @Published private(set) var passwordAssessment = PasswordStrengthEvaluator.evaluate("")

    @Published private(set) var isRunning = false
    @Published private(set) var progress: Double = 0
    @Published private(set) var phase: FileCipherPhase = .processing
    @Published private(set) var statusText = ""

    @Published var errorMessage: String?
    @Published var isShowingError = false
    @Published private(set) var successMessage: String?
    @Published private(set) var lastOutputURL: URL?

    @Published var isDropTargeted = false
    @Published var isShowingOverwriteConfirmation = false

    /// The exact string the last generation produced, so the note can be
    /// cleared only when the user actually changes it.
    private var generatedPasswordValue: String?
    private var pendingDestination: URL?
    private var cancellation: CancellationFlag?
    private var cancellables: Set<AnyCancellable> = []

    init() {
        passwordAssessment = PasswordStrengthEvaluator.evaluate(password)

        // Files dropped on the Dock icon arrive as an Apple Event.
        NotificationCenter.default
            .publisher(for: .fileCryptOpenFile)
            .compactMap { $0.object as? URL }
            .receive(on: RunLoop.main)
            .sink { [weak self] url in
                guard let self, !self.isRunning else { return }
                self.setInputFile(url)
            }
            .store(in: &cancellables)
    }

    // MARK: - Derived state

    /// `true` when this run will produce a folder rather than a file.
    var destinationHoldsFolder: Bool {
        (mode == .encrypt && inputIsDirectory) || (mode == .decrypt && containerHoldsDirectory)
    }

    /// Labels the primary button for what is actually about to happen.
    var actionTitle: String {
        switch mode {
        case .encrypt: return inputIsDirectory ? "Encrypt Folder" : "Encrypt File"
        case .decrypt: return containerHoldsDirectory ? "Restore Folder" : "Decrypt File"
        }
    }

    var canRun: Bool {
        !isRunning && inputURL != nil && !password.isEmpty && validationMessage == nil
    }

    /// The first reason the user cannot proceed, or `nil` when all is well.
    var validationMessage: String? {
        guard inputURL != nil else { return "Choose a file to get started." }
        if password.isEmpty { return "Enter a password." }
        if password.utf8.count > EncryptionOptions.maximumPasswordByteCount {
            return "That password is too long (limit \(EncryptionOptions.maximumPasswordByteCount) bytes)."
        }
        if mode == .encrypt {
            if confirmPassword.isEmpty { return "Re-enter the password to confirm it." }
            if password != confirmPassword { return "The two passwords do not match." }
            if inputLooksEncrypted {
                return "This file already looks like a FileCrypt container."
            }
        } else {
            if !inputLooksEncrypted {
                return "This is not a FileCrypt container. Switch to Encrypt to protect it."
            }
        }
        return nil
    }

    var progressFraction: Double {
        isRunning ? max(0.02, min(progress, 1)) : 0
    }

    var phaseDescription: String {
        switch phase {
        case .derivingKey: return "Deriving key from your password…"
        case .processing: return mode == .encrypt ? "Encrypting…" : "Decrypting…"
        case .finalizing: return "Finishing up…"
        }
    }

    // MARK: - File selection

    func setInputFile(_ url: URL) {
        guard !isRunning else { return }

        let standardised = url.standardizedFileURL

        // Reject anything we cannot actually operate on *now*, rather than
        // letting the user pick a folder, type a password and only then be told
        // it was never going to work. Dropping a folder on the drop zone is an
        // easy mistake to make.
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: standardised.path, isDirectory: &isDirectory) else {
            present(error: "Could not read “\(standardised.lastPathComponent)”. Check that you can open it.")
            return
        }

        inputURL = standardised
        inputIsDirectory = isDirectory.boolValue
        successMessage = nil
        errorMessage = nil
        lastOutputURL = nil

        // A folder is never a container; only files carry a magic.
        let detected = inputIsDirectory ? false : FileCipher.looksEncrypted(standardised)
        inputLooksEncrypted = detected
        containerHoldsDirectory = detected ? FileCipher.containsDirectory(standardised) : false

        // Follow the file: a .fcrypt container means the user wants to decrypt.
        if detected, mode == .encrypt {
            mode = .decrypt
        } else if !detected, mode == .decrypt {
            mode = .encrypt
        }

        inputDetail = inputIsDirectory
            ? folderSummary(standardised)
            : describe(standardised, size: fileSize(of: standardised))
        refreshDestination()
    }

    func clearInputFile() {
        guard !isRunning else { return }
        inputURL = nil
        destinationURL = nil
        inputDetail = nil
        inputLooksEncrypted = false
        inputIsDirectory = false
        containerHoldsDirectory = false
        successMessage = nil
        lastOutputURL = nil
    }

    private func folderSummary(_ url: URL) -> String {
        let survey = try? TarWriter.survey(root: url)
        let count = survey?.summary.fileCount ?? 0
        let folders = survey?.summary.directoryCount ?? 0
        let links = survey?.summary.symbolicLinkCount ?? 0
        var parts = ["\(count) file\(count == 1 ? "" : "s")", "\(folders) folder\(folders == 1 ? "" : "s")"]
        if links > 0 { parts.append("\(links) link\(links == 1 ? "" : "s")") }
        return parts.joined(separator: " · ") + " · \(url.deletingLastPathComponent().lastPathComponent)/\(url.lastPathComponent)"
    }

    private func fileSize(of url: URL) -> Int {
        (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
    }

    private func describe(_ url: URL, size: Int) -> String {
        let formatted = ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
        return "\(formatted) · \(url.deletingLastPathComponent().lastPathComponent)/\(url.lastPathComponent)"
    }

    /// Surface a problem to the user without disturbing the current selection.
    private func present(error message: String) {
        errorMessage = message
        isShowingError = true
    }

    /// Default destination for the current input and mode.
    ///
    /// Encrypting always appends `.fcrypt`. Decrypting strips `.fcrypt` when it
    /// is there, and otherwise appends `.decrypted` to the *whole* name: a
    /// container called `payload.bin` becomes `payload.bin.decrypted`, not
    /// `payload.decrypted`. Dropping the original extension would discard
    /// information the user needs to identify the file again, and could collide
    /// with an unrelated `payload` sitting in the same folder.
    func defaultDestination(for input: URL, mode: Mode) -> URL {
        switch mode {
        case .encrypt:
            // A folder becomes a sibling `.fcrypt` container rather than
            // `Folder.fcrypt` sitting inside itself, which is what appending an
            // extension to a directory would mean.
            if inputIsDirectory {
                return input.deletingLastPathComponent()
                    .appendingPathComponent(input.lastPathComponent + ".fcrypt")
            }
            return input.appendingPathExtension("fcrypt")
        case .decrypt:
            if input.pathExtension.lowercased() == "fcrypt" {
                return input.deletingPathExtension()
            }
            return input.appendingPathExtension("decrypted")
        }
    }

    private func refreshDestination() {
        guard let inputURL else {
            destinationURL = nil
            return
        }
        destinationURL = defaultDestination(for: inputURL, mode: mode)
    }

    // MARK: - Panels

    func chooseInputFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        // A folder can be encrypted as a single container, so it is offered.
        panel.canChooseDirectories = mode == .encrypt
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        panel.prompt = "Choose"
        panel.message = mode == .encrypt
            ? "Choose the file or folder you want to encrypt."
            : "Choose the .fcrypt file you want to decrypt."
        if panel.runModal() == .OK, let url = panel.url {
            setInputFile(url)
        }
    }

    func chooseDestination() {
        guard inputURL != nil else { return }
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = destinationURL?.lastPathComponent ?? "output.fcrypt"
        panel.message = mode == .decrypt && containerHoldsDirectory
            ? "Choose a name for the restored folder."
            : "Where should the result be saved?"
        if panel.runModal() == .OK, let url = panel.url {
            destinationURL = url
        }
    }

    // MARK: - Password generation

    var generatorOptions: PasswordGeneratorOptions {
        PasswordGeneratorOptions(
            length: generatorLength,
            includeLowercase: true,
            includeUppercase: true,
            includeDigits: true,
            includeSymbols: generatorIncludeSymbols,
            excludeAmbiguous: generatorExcludeAmbiguous,
            requireEverySelectedClass: generatorRequireEveryClass
        )
    }

    var generatorPreview: String {
        (try? PasswordGenerator.summary(generatorOptions)) ?? ""
    }

    /// Replace the password with a freshly generated one.
    ///
    /// The confirmation field is filled too — the user did not choose this
    /// string, so asking them to retype it would only invite transcription
    /// errors — and the field is revealed, because a password the user cannot
    /// read is a password they cannot save.
    func generatePassword() {
        guard !isRunning else { return }
        do {
            let generated = try PasswordGenerator.generate(generatorOptions)
            password = generated
            confirmPassword = generated
            revealPassword = true
            generatedPasswordSummary = try? PasswordGenerator.summary(generatorOptions)
            errorMessage = nil
        } catch {
            present(error: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
    }

    func copyPasswordToClipboard() {
        guard !password.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(password, forType: .string)
        generatedPasswordSummary = "Copied to the clipboard"
    }

    func revealOutputInFinder() {
        guard let url = lastOutputURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    /// Point the destination somewhere specific. Used by tests to exercise
    /// destinations the save panel would not normally produce.
    func setDestinationForTesting(_ url: URL) {
        destinationURL = url
    }

    // MARK: - Running

    func primaryAction() {
        guard let inputURL else { return }
        let destination = destinationURL ?? defaultDestination(for: inputURL, mode: mode)

        // A directory at the destination is not something to "replace" *when
        // the result is a file* — reporting it here avoids a misleading prompt
        // and a full encrypt-then-fail cycle. When the result is itself a
        // folder, an existing folder at that path is the ordinary overwrite
        // case and belongs at the confirmation below.
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDirectory) {
            if isDirectory.boolValue, !destinationHoldsFolder {
                present(error: "\u{201C}\(destination.lastPathComponent)\u{201D} is a folder. "
                    + "Choose a file name for the result, or pick another folder.")
                return
            }
            pendingDestination = destination
            isShowingOverwriteConfirmation = true
            return
        }
        start(input: inputURL, destination: destination)
    }

    func confirmOverwrite() {
        guard let inputURL, let destination = pendingDestination else { return }
        pendingDestination = nil
        start(input: inputURL, destination: destination)
    }

    func cancelOverwrite() {
        pendingDestination = nil
    }

    func cancel() {
        cancellation?.cancel()
        statusText = "Cancelling…"
    }

    private func start(input: URL, destination: URL) {
        guard !isRunning else { return }

        isRunning = true
        progress = 0
        phase = .derivingKey
        successMessage = nil
        errorMessage = nil
        lastOutputURL = nil
        statusText = "\(mode.workingVerb) \(input.lastPathComponent)"

        let flag = CancellationFlag()
        cancellation = flag

        let mode = self.mode
        let password = self.password
        let preset = keyStrength

        Task { [weak self] in
            guard let self else { return }

            let progressHandler: @Sendable (Double) -> Void = { value in
                Task { @MainActor [weak self] in
                    self?.progress = value
                }
            }
            let phaseHandler: @Sendable (FileCipherPhase) -> Void = { value in
                Task { @MainActor [weak self] in
                    self?.phase = value
                }
            }

            do {
                let produced: URL
                switch mode {
                case .encrypt:
                    produced = try await CryptRunner.encrypt(
                        input: input,
                        output: destination,
                        password: password,
                        options: EncryptionOptions(
                            chunkSize: EncryptionOptions.defaultChunkSize,
                            memoryKiB: preset.memoryKiB,
                            timeCost: preset.timeCost,
                            parallelism: preset.parallelism
                        ),
                        cancellation: flag,
                        progress: progressHandler,
                        phase: phaseHandler
                    )
                case .decrypt:
                    produced = try await CryptRunner.decrypt(
                        input: input,
                        output: destination,
                        password: password,
                        cancellation: flag,
                        progress: progressHandler,
                        phase: phaseHandler
                    )
                }
                self.finishSuccess(output: produced, mode: mode)
            } catch {
                self.finishFailure(error)
            }
        }
    }

    private func finishSuccess(output: URL, mode: Mode) {
        isRunning = false
        cancellation = nil
        progress = 1
        lastOutputURL = output
        successMessage = "\(mode == .encrypt ? "Encrypted" : "Decrypted") to \(output.lastPathComponent)"
        statusText = ""
        // Do not keep the password alive in the UI longer than necessary.
        password = ""
        confirmPassword = ""
    }

    private func finishFailure(_ error: Error) {
        isRunning = false
        cancellation = nil
        progress = 0
        statusText = ""

        if let cryptoError = error as? CryptoError, cryptoError == .cancelled {
            successMessage = nil
            errorMessage = nil
            return
        }

        var message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        if let suggestion = (error as? LocalizedError)?.recoverySuggestion, !suggestion.isEmpty {
            message += "\n\n\(suggestion)"
        }
        errorMessage = message
        isShowingError = true
    }
}
