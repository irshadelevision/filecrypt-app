//
//  AppModelTests.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import FileCryptCore
import XCTest

@testable import FileCrypt

/// Tests for the layer that actually implements the user-facing behaviour:
/// which mode the window is in, what the destination is called, when the
/// primary button is enabled, what happens on overwrite, and what a full
/// round trip through the model leaves on disk.
@MainActor
final class AppModelTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("FileCryptAppTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratch, FileManager.default.fileExists(atPath: scratch.path) {
            try? FileManager.default.removeItem(at: scratch)
        }
        scratch = nil
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    private func path(_ name: String) -> URL {
        scratch.appendingPathComponent(name)
    }

    private func makeFile(_ name: String, bytes: Int = 4_000, seed: UInt64 = 0xABCD) throws -> URL {
        var state = seed
        var data = Data(count: bytes)
        for index in 0..<bytes {
            state ^= state >> 12
            state ^= state << 25
            state ^= state >> 27
            data[index] = UInt8(truncatingIfNeeded: state &* 0x2545_F491_4F6C_DD1D)
        }
        let url = path(name)
        try data.write(to: url)
        return url
    }

    /// Encrypt a file using the core directly, so the model can be tested
    /// against a genuine container.
    @discardableResult
    private func makeContainer(_ name: String, password: String, bytes: Int = 4_000) throws -> URL {
        let plain = try makeFile("source-for-\(name)", bytes: bytes)
        let container = path(name)
        try FileCipher.encryptFile(
            at: plain,
            to: container,
            password: password,
            options: EncryptionOptions(chunkSize: 1_024, memoryKiB: 1_024, timeCost: 1, parallelism: 1)
        )
        try? FileManager.default.removeItem(at: plain)
        return container
    }

    private func makeModel() -> AppModel {
        let model = AppModel()
        model.keyStrength = .standard
        return model
    }

    /// Wait until the model's running flag drops, i.e. the worker task finished.
    private func waitForCompletion(_ model: AppModel, timeout: TimeInterval = 60) async {
        let deadline = Date().addingTimeInterval(timeout)
        while model.isRunning, Date() < deadline {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    // MARK: - File selection and mode detection

    func testSelectingAPlainFileSwitchesToEncryptAndNamesTheContainer() throws {
        let file = try makeFile("report.txt")
        let model = makeModel()
        model.mode = .decrypt // deliberately wrong; selecting a plain file must correct it

        model.setInputFile(file)

        XCTAssertEqual(model.mode, .encrypt)
        XCTAssertFalse(model.inputLooksEncrypted)
        XCTAssertEqual(model.inputURL, file)
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "report.txt.fcrypt")
        XCTAssertNotNil(model.inputDetail)
    }

    func testSelectingAContainerSwitchesToDecryptAndStripsTheExtension() throws {
        let container = try makeContainer("report.pdf.fcrypt", password: "pw")
        let model = makeModel()
        model.mode = .encrypt // deliberately wrong

        model.setInputFile(container)

        XCTAssertEqual(model.mode, .decrypt)
        XCTAssertTrue(model.inputLooksEncrypted)
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "report.pdf")
    }

    func testSwitchingModeManuallyRecomputesTheDestination() throws {
        let file = try makeFile("notes.md")
        let model = makeModel()
        model.setInputFile(file)
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "notes.md.fcrypt")

        model.mode = .decrypt
        // The file is not a container, so the destination is the fallback name,
        // which keeps the original extension.
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "notes.md.decrypted")
    }

    func testDecryptingAFileWithoutTheFcryptExtensionUsesAFallbackName() throws {
        let container = try makeContainer("payload.bin", password: "pw")
        let model = makeModel()
        model.setInputFile(container)
        XCTAssertEqual(model.mode, .decrypt)
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "payload.bin.decrypted")
    }

    func testSelectingAFolderIsAcceptedForEncryption() throws {
        let folder = path("project")
        try FileManager.default.createDirectory(
            at: folder.appendingPathComponent("src"), withIntermediateDirectories: true)
        try Data("readme".utf8).write(to: folder.appendingPathComponent("README.md"))
        try Data("code".utf8).write(to: folder.appendingPathComponent("src/main.swift"))

        let model = makeModel()
        model.setInputFile(folder)

        XCTAssertTrue(model.inputIsDirectory)
        XCTAssertEqual(model.mode, .encrypt)
        XCTAssertEqual(model.inputURL, folder)
        XCTAssertEqual(model.actionTitle, "Encrypt Folder")

        // The container is a sibling, not `project.fcrypt` inside the folder.
        XCTAssertEqual(model.destinationURL?.lastPathComponent, "project.fcrypt")
        XCTAssertEqual(
            model.destinationURL?.deletingLastPathComponent(),
            folder.deletingLastPathComponent()
        )

        // The summary should describe the tree rather than claim a byte size.
        XCTAssertTrue(model.inputDetail?.contains("2 files") == true, model.inputDetail ?? "nil")
        XCTAssertTrue(model.inputDetail?.contains("2 folders") == true, model.inputDetail ?? "nil")
    }

    func testAFolderCannotBeSelectedForDecryption() throws {
        let folder = path("not-a-container")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        let model = makeModel()
        model.mode = .decrypt

        // A folder is not a container, so decrypt validation must refuse it
        // without the model silently switching modes.
        model.setInputFile(folder)
        XCTAssertTrue(model.inputIsDirectory)
        XCTAssertFalse(model.inputLooksEncrypted)
        XCTAssertNotNil(model.validationMessage)
    }

    func testFolderRoundTripThroughTheModel() async throws {
        let folder = path("roundtrip-folder")
        try FileManager.default.createDirectory(
            at: folder.appendingPathComponent("nested"), withIntermediateDirectories: true)
        let payload = Data((0..<20_000).map { UInt8($0 % 251) })
        try payload.write(to: folder.appendingPathComponent("nested/data.bin"))
        try Data("notes".utf8).write(to: folder.appendingPathComponent("notes.txt"))

        // --- encrypt ------------------------------------------------------
        let encryptor = makeModel()
        encryptor.setInputFile(folder)
        encryptor.password = "folder passphrase"
        encryptor.confirmPassword = "folder passphrase"
        XCTAssertEqual(encryptor.actionTitle, "Encrypt Folder")
        XCTAssertTrue(encryptor.canRun)

        encryptor.primaryAction()
        await waitForCompletion(encryptor)

        XCTAssertFalse(encryptor.isShowingError, encryptor.errorMessage ?? "")
        let container = try XCTUnwrap(encryptor.lastOutputURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: container.path))

        // --- decrypt ------------------------------------------------------
        let decryptor = makeModel()
        decryptor.setInputFile(container)

        XCTAssertEqual(decryptor.mode, .decrypt)
        XCTAssertTrue(decryptor.containerHoldsDirectory)
        XCTAssertEqual(decryptor.actionTitle, "Restore Folder")
        // Restoring beside the container would collide with the original, so
        // the default name is the container's own name without the extension.
        XCTAssertEqual(decryptor.destinationURL?.lastPathComponent, "roundtrip-folder")

        decryptor.password = "folder passphrase"
        XCTAssertTrue(decryptor.canRun)
        decryptor.primaryAction()

        // `roundtrip-folder` still exists, so restoring over it must ask first
        // rather than silently replacing the original.
        XCTAssertTrue(
            decryptor.isShowingOverwriteConfirmation,
            "restoring onto an existing folder must ask before replacing it"
        )
        XCTAssertFalse(decryptor.isRunning)
        decryptor.confirmOverwrite()
        await waitForCompletion(decryptor)

        XCTAssertFalse(decryptor.isShowingError, decryptor.errorMessage ?? "")
        let restored = try XCTUnwrap(
            decryptor.lastOutputURL,
            "folder restore failed: \(decryptor.errorMessage ?? "no error")"
        )

        // The restored folder is the folder, not a folder containing it.
        XCTAssertEqual(
            try Data(contentsOf: restored.appendingPathComponent("nested/data.bin")),
            payload
        )
        XCTAssertEqual(
            try Data(contentsOf: restored.appendingPathComponent("notes.txt")),
            Data("notes".utf8)
        )
    }

    func testWrongPasswordOnAFolderArchiveLeavesNothingBehind() async throws {
        let folder = path("locked-folder")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try Data("secret".utf8).write(to: folder.appendingPathComponent("s.txt"))

        let encryptor = makeModel()
        encryptor.setInputFile(folder)
        encryptor.password = "right"
        encryptor.confirmPassword = "right"
        encryptor.primaryAction()
        await waitForCompletion(encryptor)
        let container = try XCTUnwrap(
            encryptor.lastOutputURL,
            "folder encryption failed: \(encryptor.errorMessage ?? "no error")"
        )

        let decryptor = makeModel()
        decryptor.setInputFile(container)
        decryptor.password = "wrong"
        decryptor.primaryAction()
        if decryptor.isShowingOverwriteConfirmation {
            decryptor.confirmOverwrite()
        }
        await waitForCompletion(decryptor)

        XCTAssertTrue(decryptor.isShowingError)
        XCTAssertNil(decryptor.lastOutputURL)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: path("locked-folder.decrypted").path)
        )
    }

    func testSelectingAMissingFileIsRefused() throws {
        let model = makeModel()
        model.setInputFile(path("does-not-exist.bin"))
        XCTAssertNil(model.inputURL)
        XCTAssertTrue(model.isShowingError)
    }

    func testClearingTheSelectionResetsEverything() throws {
        let container = try makeContainer("c.fcrypt", password: "pw")
        let model = makeModel()
        model.setInputFile(container)
        model.password = "pw"

        model.clearInputFile()

        XCTAssertNil(model.inputURL)
        XCTAssertNil(model.destinationURL)
        XCTAssertNil(model.inputDetail)
        XCTAssertFalse(model.inputLooksEncrypted)
    }

    // MARK: - Validation

    func testValidationWithoutAFile() {
        let model = makeModel()
        XCTAssertEqual(model.validationMessage, "Choose a file to get started.")
        XCTAssertFalse(model.canRun)
    }

    func testValidationRequiresAPassword() throws {
        let file = try makeFile("v.txt")
        let model = makeModel()
        model.setInputFile(file)
        model.confirmPassword = ""

        XCTAssertEqual(model.validationMessage, "Enter a password.")
        XCTAssertFalse(model.canRun)

        model.password = "something"
        XCTAssertEqual(model.validationMessage, "Re-enter the password to confirm it.")
        XCTAssertFalse(model.canRun)
    }

    func testValidationRejectsMismatchedPasswords() throws {
        let file = try makeFile("v.txt")
        let model = makeModel()
        model.setInputFile(file)
        model.password = "correct horse"
        model.confirmPassword = "correct hors"

        XCTAssertEqual(model.validationMessage, "The two passwords do not match.")
        XCTAssertFalse(model.canRun)

        model.confirmPassword = "correct horse"
        XCTAssertNil(model.validationMessage)
        XCTAssertTrue(model.canRun)
    }

    func testValidationRefusesToEncryptAFileThatIsAlreadyAContainer() throws {
        let container = try makeContainer("already.fcrypt", password: "pw")
        let model = makeModel()
        model.setInputFile(container)   // lands in decrypt mode
        model.mode = .encrypt           // user overrides
        model.password = "pw"
        model.confirmPassword = "pw"

        XCTAssertNotNil(model.validationMessage)
        XCTAssertFalse(model.canRun)
    }

    func testValidationRefusesToDecryptSomethingThatIsNotAContainer() throws {
        let file = try makeFile("plain.bin")
        let model = makeModel()
        model.setInputFile(file)        // lands in encrypt mode
        model.mode = .decrypt           // user overrides
        model.password = "pw"

        XCTAssertEqual(
            model.validationMessage,
            "This is not a FileCrypt container. Switch to Encrypt to protect it."
        )
        XCTAssertFalse(model.canRun)
    }

    func testValidationRejectsAnOverlongPassword() throws {
        let file = try makeFile("v.txt")
        let model = makeModel()
        model.setInputFile(file)
        model.password = String(repeating: "a", count: EncryptionOptions.maximumPasswordByteCount + 1)
        model.confirmPassword = model.password

        XCTAssertNotNil(model.validationMessage)
        XCTAssertFalse(model.canRun)
        XCTAssertTrue(model.validationMessage?.contains("too long") == true)
    }

    // MARK: - Round trip through the model

    func testFullEncryptThenDecryptRoundTripThroughTheModel() async throws {
        let plain = try makeFile("roundtrip.bin", bytes: 9_000)
        let originalBytes = try Data(contentsOf: plain)

        // --- encrypt ------------------------------------------------------
        let encryptor = makeModel()
        encryptor.setInputFile(plain)
        XCTAssertEqual(encryptor.mode, .encrypt)
        encryptor.password = "a strong passphrase"
        encryptor.confirmPassword = "a strong passphrase"
        XCTAssertTrue(encryptor.canRun)

        encryptor.primaryAction()
        XCTAssertTrue(encryptor.isRunning, "the operation must start synchronously")
        XCTAssertFalse(encryptor.canRun, "the button must be disabled while running")

        await waitForCompletion(encryptor)

        XCTAssertFalse(encryptor.isRunning)
        XCTAssertNil(encryptor.errorMessage)
        XCTAssertFalse(encryptor.isShowingError)

        let container = try XCTUnwrap(encryptor.destinationURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: container.path))
        XCTAssertEqual(encryptor.lastOutputURL, container)
        XCTAssertNotNil(encryptor.successMessage)
        XCTAssertEqual(encryptor.progress, 1.0, accuracy: 0.0001)

        // The password must not linger in the UI after a successful run.
        XCTAssertTrue(encryptor.password.isEmpty)
        XCTAssertTrue(encryptor.confirmPassword.isEmpty)

        // The original is untouched.
        XCTAssertEqual(try Data(contentsOf: plain), originalBytes)

        // --- decrypt ------------------------------------------------------
        let decryptor = makeModel()
        decryptor.setInputFile(container)
        XCTAssertEqual(decryptor.mode, .decrypt)
        decryptor.password = "a strong passphrase"
        XCTAssertTrue(decryptor.canRun)

        decryptor.primaryAction()

        // `roundtrip.bin` still exists, so the model must ask before replacing
        // it rather than silently overwriting the user's original file.
        XCTAssertTrue(
            decryptor.isShowingOverwriteConfirmation,
            "decrypting back onto an existing file must ask first"
        )
        XCTAssertFalse(decryptor.isRunning)
        decryptor.confirmOverwrite()

        await waitForCompletion(decryptor)

        XCTAssertFalse(decryptor.isShowingError, decryptor.errorMessage ?? "")
        let restored = try XCTUnwrap(
            decryptor.lastOutputURL,
            "folder restore failed: \(decryptor.errorMessage ?? "no error")"
        )
        XCTAssertEqual(restored.lastPathComponent, "roundtrip.bin")
        XCTAssertEqual(try Data(contentsOf: restored), originalBytes)
    }

    func testWrongPasswordThroughTheModelSurfacesAnErrorAndLeavesNoFile() async throws {
        let container = try makeContainer("lock.fcrypt", password: "right-password")

        let model = makeModel()
        model.setInputFile(container)
        model.password = "wrong-password"
        XCTAssertTrue(model.canRun)

        model.primaryAction()
        await waitForCompletion(model)

        XCTAssertFalse(model.isRunning)
        XCTAssertTrue(model.isShowingError)
        XCTAssertTrue(
            model.errorMessage?.contains("password is incorrect") == true,
            "unexpected message: \(model.errorMessage ?? "nil")"
        )
        XCTAssertNil(model.lastOutputURL)

        let destination = model.defaultDestination(for: container, mode: .decrypt)
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testProgressStartsAtZeroAndStatusTracksTheOperation() async throws {
        let plain = try makeFile("progress.bin", bytes: 200_000)
        let model = makeModel()
        model.setInputFile(plain)
        model.password = "pw"
        model.confirmPassword = "pw"

        model.primaryAction()
        XCTAssertEqual(model.progress, 0)
        XCTAssertFalse(model.statusText.isEmpty)
        XCTAssertEqual(model.phase, .derivingKey)

        await waitForCompletion(model)
        XCTAssertEqual(model.progress, 1.0, accuracy: 0.0001)
        XCTAssertTrue(model.statusText.isEmpty)
    }

    // MARK: - Overwrite handling

    func testAnExistingDestinationAsksBeforeRunning() async throws {
        let plain = try makeFile("collide.bin", bytes: 1_000)
        let container = path("collide.bin.fcrypt")
        try Data("old contents".utf8).write(to: container)

        let model = makeModel()
        model.setInputFile(plain)
        model.password = "pw"
        model.confirmPassword = "pw"
        XCTAssertEqual(model.destinationURL, container)

        model.primaryAction()

        // It must ask, and must not have started.
        XCTAssertTrue(model.isShowingOverwriteConfirmation)
        XCTAssertFalse(model.isRunning)
        XCTAssertEqual(try Data(contentsOf: container), Data("old contents".utf8))

        model.confirmOverwrite()
        await waitForCompletion(model)

        XCTAssertFalse(model.isShowingError, model.errorMessage ?? "")
        XCTAssertNotEqual(try Data(contentsOf: container), Data("old contents".utf8))

        // And the replacement is a real container.
        let restored = path("collide.restored")
        try FileCipher.decryptFile(at: container, to: restored, password: "pw")
        XCTAssertEqual(try Data(contentsOf: restored), try Data(contentsOf: plain))
    }

    func testDecliningTheOverwriteLeavesEverythingAlone() throws {
        let plain = try makeFile("decline.bin", bytes: 1_000)
        let container = path("decline.bin.fcrypt")
        try Data("untouched".utf8).write(to: container)

        let model = makeModel()
        model.setInputFile(plain)
        model.password = "pw"
        model.confirmPassword = "pw"
        model.primaryAction()
        XCTAssertTrue(model.isShowingOverwriteConfirmation)

        model.cancelOverwrite()

        XCTAssertFalse(model.isRunning)
        XCTAssertEqual(try Data(contentsOf: container), Data("untouched".utf8))

        // Dismissing the sheet without choosing must not leave the action armed.
        // (The dialog sets `isShowingOverwriteConfirmation` itself; the pending
        // destination is what matters here.)
        model.primaryAction()
        XCTAssertTrue(model.isShowingOverwriteConfirmation)
        model.cancelOverwrite()
        XCTAssertFalse(model.isRunning)
    }

    func testADirectoryDestinationIsReportedRatherThanOfferedForReplacement() throws {
        let plain = try makeFile("into-dir.bin", bytes: 500)
        let model = makeModel()
        model.setInputFile(plain)
        model.password = "pw"
        model.confirmPassword = "pw"

        // Point the destination at a real directory.
        let directory = path("destination-folder")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        model.setDestinationForTesting(directory)

        model.primaryAction()

        // It must not ask to "replace" a folder, and must not start.
        XCTAssertFalse(model.isShowingOverwriteConfirmation)
        XCTAssertFalse(model.isRunning)
        XCTAssertTrue(model.isShowingError)
        XCTAssertTrue(
            model.errorMessage?.contains("is a folder") == true,
            "unexpected message: \(model.errorMessage ?? "nil")"
        )

        // The directory is untouched.
        XCTAssertTrue(
            try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty
        )
    }

    // MARK: - Cancellation

    func testCancellingLeavesNoOutputAndNoErrorBanner() async throws {
        // Big enough that it cannot finish before the cancel lands.
        let plain = try makeFile("cancelme.bin", bytes: 12 * 1_024 * 1_024)
        let model = makeModel()
        model.setInputFile(plain)
        model.password = "pw"
        model.confirmPassword = "pw"

        model.primaryAction()
        XCTAssertTrue(model.isRunning)

        model.cancel()
        await waitForCompletion(model)

        XCTAssertFalse(model.isRunning)
        XCTAssertFalse(model.isShowingError, "a user-requested cancel is not an error")
        XCTAssertNil(model.lastOutputURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path("cancelme.bin.fcrypt").path))

        let leftovers = try FileManager.default
            .contentsOfDirectory(atPath: scratch.path)
            .filter { $0.contains(".part") }
        XCTAssertTrue(leftovers.isEmpty, "cancel left temporary files: \(leftovers)")
    }

    // MARK: - Password strength wiring

    func testPasswordAssessmentTracksThePassword() {
        let model = makeModel()
        XCTAssertEqual(model.passwordAssessment.strength, .veryWeak)

        model.password = "password"
        XCTAssertEqual(model.passwordAssessment.strength, .veryWeak)

        model.password = "correct-horse-battery-staple-92"
        XCTAssertGreaterThanOrEqual(model.passwordAssessment.strength, .strong)
    }

    // MARK: - Destination naming

    func testDefaultDestinationNamingRules() {
        let model = makeModel()

        let plain = URL(fileURLWithPath: "/tmp/a.txt")
        XCTAssertEqual(
            model.defaultDestination(for: plain, mode: .encrypt).path,
            "/tmp/a.txt.fcrypt"
        )
        XCTAssertEqual(
            model.defaultDestination(for: plain, mode: .decrypt).path,
            "/tmp/a.txt.decrypted"
        )

        let container = URL(fileURLWithPath: "/tmp/a.txt.fcrypt")
        XCTAssertEqual(
            model.defaultDestination(for: container, mode: .decrypt).path,
            "/tmp/a.txt"
        )

        // Case-insensitive extension, and a file that is only an extension.
        let shouty = URL(fileURLWithPath: "/tmp/b.FCRYPT")
        XCTAssertEqual(model.defaultDestination(for: shouty, mode: .decrypt).path, "/tmp/b")

        let dotted = URL(fileURLWithPath: "/tmp/.fcrypt")
        XCTAssertEqual(
            model.defaultDestination(for: dotted, mode: .decrypt).path,
            "/tmp/.fcrypt.decrypted"
        )
    }
}
