//
//  ContentView.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import FileCryptCore
import SwiftUI
import UniformTypeIdentifiers

/// The main window.
///
/// Layout is a fixed three-step column. The order never changes, the numbering
/// only appears on steps that are actually relevant to the current mode, and
/// steps that cannot be acted on yet are dimmed rather than hidden — so the
/// window does not jump around as the user works through it.
struct ContentView: View {

    @ObservedObject var model: AppModel
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case password
        case confirm
    }

    private var encrypting: Bool { model.mode == .encrypt }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.sectionSpacing) {
            header
            modePicker
            fileCard
            passwordCard
            keyStrengthCard
            actionArea
        }
        .padding(Theme.Metrics.contentPadding)
        .frame(width: Theme.Metrics.windowWidth)
        .background(Theme.windowBackground)
        .alert("Something went wrong", isPresented: $model.isShowingError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "Unknown error.")
        }
        .confirmationDialog(
            "Replace the existing file?",
            isPresented: $model.isShowingOverwriteConfirmation,
            titleVisibility: .visible
        ) {
            Button("Replace", role: .destructive) { model.confirmOverwrite() }
            Button("Cancel", role: .cancel) { model.cancelOverwrite() }
        } message: {
            Text("A file with that name is already in the destination folder. It will be replaced, and this cannot be undone.")
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 11) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 38, height: 38)
                .background(Theme.accentGradient, in: RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 1) {
                Text("FileCrypt")
                    .font(Theme.Text.title)
                Text("AES-256-GCM · Argon2id → HKDF-SHA256")
                    .font(Theme.Text.subtitle)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 0)
        }
    }

    // MARK: - Mode

    private var modePicker: some View {
        Picker("", selection: $model.mode) {
            ForEach(AppModel.Mode.allCases) { mode in
                Label(mode.title, systemImage: mode.symbolName).tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(model.isRunning)
        .accessibilityLabel("Operation")
    }

    // MARK: - Step 1: file

    private var fileCard: some View {
        StepCard(number: 1, title: model.mode == .encrypt ? "Choose a file or folder" : "Choose a container") {
            VStack(spacing: 10) {
                dropZone
                if model.inputURL != nil {
                    secondaryActions
                }
            }
        }
    }

    private var dropZone: some View {
        ZStack {
            RoundedRectangle(cornerRadius: Theme.Metrics.dropZoneRadius, style: .continuous)
                .fill(model.isDropTargeted ? Theme.accentSoft : Theme.dropFill)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.Metrics.dropZoneRadius, style: .continuous)
                        .strokeBorder(
                            model.isDropTargeted ? Theme.accent : Theme.dropStroke,
                            style: StrokeStyle(
                                lineWidth: model.isDropTargeted ? 2 : 1.25,
                                dash: model.inputURL == nil ? [6, 4] : []
                            )
                        )
                )

            if let inputURL = model.inputURL {
                chosenFile(inputURL)
            } else {
                emptyDropZone
            }
        }
        .frame(height: model.inputURL == nil ? Theme.Metrics.dropZoneHeight + 12 : Theme.Metrics.dropZoneHeight)
        .animation(.easeOut(duration: 0.15), value: model.isDropTargeted)
        .animation(.easeOut(duration: 0.15), value: model.inputURL)
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $model.isDropTargeted) { providers in
            handleDrop(providers)
        }
    }

    private func chosenFile(_ url: URL) -> some View {
        HStack(spacing: 10) {
            Image(systemName: model.inputLooksEncrypted
                  ? "lock.doc.fill"
                  : (model.inputIsDirectory ? "folder.fill" : "doc.fill"))
                .font(.system(size: 20))
                .foregroundStyle(Theme.accent)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 1) {
                Text(url.lastPathComponent)
                    .font(Theme.Text.bodyMedium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let detail = model.inputDetail {
                    Text(detail)
                        .font(Theme.Text.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
    }

    private var emptyDropZone: some View {
        VStack(spacing: 7) {
            Image(systemName: "arrow.down.doc")
                .font(.system(size: 24, weight: .light))
                .foregroundStyle(Theme.accent)
            Text(encrypting ? "Drag a file or folder here" : "Drag a .fcrypt file here")
                .font(Theme.Text.bodyMedium)
            Button(encrypting ? "Choose File or Folder…" : "Choose File…") { model.chooseInputFile() }
                .controlSize(.small)
        }
        .padding(.vertical, 14)
    }

    private var secondaryActions: some View {
        HStack(spacing: 8) {
            Button("Change…") { model.chooseInputFile() }
                .disabled(model.isRunning)
            Button("Remove") { model.clearInputFile() }
                .disabled(model.isRunning)

            Spacer(minLength: 8)

            if let destination = model.destinationURL {
                Button {
                    model.chooseDestination()
                } label: {
                    Label(
                        destination.lastPathComponent,
                        systemImage: model.destinationHoldsFolder ? "folder.badge.plus" : "doc.badge.plus"
                    )
                    .lineLimit(1)
                    .truncationMode(.middle)
                }
                .help(model.destinationHoldsFolder
                      ? "Restore into \(destination.path)"
                      : "Save as \(destination.path)")
                .disabled(model.isRunning)
            }
        }
        .controlSize(.small)
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }

        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
            var resolved: URL?
            switch item {
            case let data as Data:
                resolved = URL(dataRepresentation: data, relativeTo: nil)
            case let url as URL:
                resolved = url
            case let string as String:
                resolved = URL(string: string)
            default:
                resolved = nil
            }

            guard let url = resolved else { return }
            Task { @MainActor in
                model.setInputFile(url)
            }
        }
        return true
    }

    // MARK: - Step 2: password

    private var passwordCard: some View {
        StepCard(
            number: 2,
            title: encrypting ? "Create a password" : "Enter the password",
            isRelevant: model.inputURL != nil
        ) {
            VStack(alignment: .leading, spacing: 10) {
                passwordRow

                if encrypting {
                    confirmRow
                    strengthMeter
                    generatorRow
                    generatedNote
                }
            }
        }
    }

    private var passwordRow: some View {
        HStack(spacing: 6) {
            Group {
                if model.revealPassword {
                    TextField("Password", text: $model.password)
                        .font(encrypting ? Theme.Text.mono : Theme.Text.body)
                } else {
                    SecureField("Password", text: $model.password)
                        .font(Theme.Text.body)
                }
            }
            .textFieldStyle(.roundedBorder)
            .focused($focusedField, equals: .password)
            .disabled(model.isRunning)
            .onSubmit { focusedField = encrypting ? .confirm : nil }

            Button {
                model.revealPassword.toggle()
            } label: {
                Image(systemName: model.revealPassword ? "eye.slash" : "eye")
                    .frame(width: 16)
            }
            .buttonStyle(.borderless)
            .help(model.revealPassword ? "Hide password" : "Show password")
            .disabled(model.isRunning)
            .accessibilityLabel(model.revealPassword ? "Hide password" : "Show password")
        }
    }

    private var confirmRow: some View {
        SecureField("Confirm password", text: $model.confirmPassword)
            .textFieldStyle(.roundedBorder)
            .font(Theme.Text.body)
            .focused($focusedField, equals: .confirm)
            .disabled(model.isRunning)
            .overlay(alignment: .trailing) {
                if !model.confirmPassword.isEmpty, model.confirmPassword != model.password {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.system(size: 11))
                        .padding(.trailing, 7)
                        .accessibilityLabel("The passwords do not match")
                }
            }
    }

    private var strengthMeter: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                GeometryReader { geometry in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Theme.meterTrack)
                        Capsule()
                            .fill(Theme.strengthColor(model.passwordAssessment.strength))
                            .frame(width: geometry.size.width * fillFraction)
                    }
                }
                .frame(height: 4)

                Text(model.password.isEmpty ? "—" : model.passwordAssessment.strength.label)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(
                        model.password.isEmpty
                            ? Color.secondary
                            : Theme.strengthColor(model.passwordAssessment.strength)
                    )
                    .frame(width: 62, alignment: .trailing)
            }

            if let suggestion = model.passwordAssessment.suggestions.first, !model.password.isEmpty {
                Text(suggestion)
                    .font(Theme.Text.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .animation(.easeOut(duration: 0.18), value: model.passwordAssessment.strength)
    }

    private var fillFraction: Double {
        guard !model.password.isEmpty else { return 0 }
        return min(max((model.passwordAssessment.entropyBits + 8) / 128.0, 0.04), 1)
    }

    private var generatorRow: some View {
        HStack(spacing: 8) {
            Button {
                model.generatePassword()
            } label: {
                Label("Generate", systemImage: "wand.and.stars")
            }
            .controlSize(.small)
            .disabled(model.isRunning)
            .help("Create a strong random password and show it")

            Menu {
                Toggle("Include symbols", isOn: $model.generatorIncludeSymbols)
                Toggle("Avoid look-alike characters", isOn: $model.generatorExcludeAmbiguous)
                Toggle("Use every selected character type", isOn: $model.generatorRequireEveryClass)
            } label: {
                Image(systemName: "gearshape")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .disabled(model.isRunning)
            .help("Generator options")

            Spacer(minLength: 8)

            Text("Length")
                .font(Theme.Text.caption)
                .foregroundStyle(.secondary)

            Stepper(value: $model.generatorLength, in: PasswordGenerator.minimumLength...64) {
                Text("\(model.generatorLength)")
                    .font(.system(size: 11, weight: .medium).monospacedDigit())
                    .frame(minWidth: 18, alignment: .trailing)
            }
            .controlSize(.small)
            .disabled(model.isRunning)
            .help(model.generatorPreview)
        }
    }

    @ViewBuilder
    private var generatedNote: some View {
        if let summary = model.generatedPasswordSummary {
            HStack(spacing: 7) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)

                Text("\(summary). Save it now — it cannot be recovered.")
                    .font(Theme.Text.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 0)

                Button("Copy") { model.copyPasswordToClipboard() }
                    .controlSize(.mini)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(
                Color.orange.opacity(0.10),
                in: RoundedRectangle(cornerRadius: Theme.Metrics.controlRadius, style: .continuous)
            )
            .transition(.opacity)
            .animation(.easeOut(duration: 0.18), value: summary)
        }
    }

    // MARK: - Step 3: key derivation

    private var keyStrengthCard: some View {
        StepCard(
            number: encrypting ? 3 : nil,
            title: "Key derivation strength",
            isRelevant: encrypting && model.inputURL != nil
        ) {
            VStack(alignment: .leading, spacing: 7) {
                Picker("", selection: $model.keyStrength) {
                    ForEach(KeyStrengthPreset.allCases) { preset in
                        Text(preset.title).tag(preset)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .disabled(model.isRunning)

                Text(model.keyStrength.detail)
                    .font(Theme.Text.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Action

    private var actionArea: some View {
        VStack(alignment: .leading, spacing: 10) {
            if model.isRunning {
                runningIndicator
            } else if let success = model.successMessage {
                successBanner(success)
            } else if let problem = model.validationMessage {
                Label(problem, systemImage: "info.circle")
                    .font(Theme.Text.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 10) {
                if model.isRunning {
                    Button("Cancel") { model.cancel() }
                        .controlSize(.large)
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                } else {
                    Button(model.actionTitle) { model.primaryAction() }
                        .controlSize(.large)
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.canRun)
                    Spacer()
                }
            }

            // The consequences of losing the password are the single most
            // important thing on this screen, so it is presented as a bordered
            // notice rather than as fine print the eye slides past.
            cautionNotice
        }
    }

    private var cautionNotice: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: "key.slash")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .padding(.top, 1)

            Text("Your password is never stored. If you lose it, the file cannot be recovered.")
                .font(Theme.Text.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(
            Color.primary.opacity(0.035),
            in: RoundedRectangle(cornerRadius: Theme.Metrics.controlRadius, style: .continuous)
        )
    }

    private var runningIndicator: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(model.statusText.isEmpty ? model.phaseDescription : model.statusText)
                    .font(Theme.Text.bodyMedium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Text("\(Int((model.progress * 100).rounded()))%")
                    .font(.system(size: 11.5, weight: .medium).monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            ProgressView(value: model.progressFraction)
                .progressViewStyle(.linear)
                .tint(Theme.accent)
        }
    }

    private func successBanner(_ message: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.seal.fill")
                .foregroundStyle(.green)
            Text(message)
                .font(Theme.Text.bodyMedium)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
            Button("Show in Finder") { model.revealOutputInFinder() }
                .controlSize(.small)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            Color.green.opacity(0.10),
            in: RoundedRectangle(cornerRadius: Theme.Metrics.controlRadius, style: .continuous)
        )
    }
}

// MARK: - Building blocks

/// The window's main action.
///
/// `.borderedProminent` resolves to flat grey whenever the window is not key —
/// which is exactly the state a headless render sees, and also what the user
/// sees while another app has focus. This draws its own fill so the primary
/// action always reads as the primary action.
private struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 22)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: Theme.Metrics.controlRadius, style: .continuous)
                    .fill(Theme.accentGradient)
                    .opacity(isEnabled ? (configuration.isPressed ? 0.82 : 1) : 0.32)
            )
            .contentShape(RoundedRectangle(cornerRadius: Theme.Metrics.controlRadius, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// One numbered step of the form.
///
/// `isRelevant: false` dims the card instead of hiding it, so the window keeps
/// a stable shape while still showing the user which step is live.
private struct StepCard<Content: View>: View {
    let number: Int?
    let title: String
    var isRelevant: Bool = true
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.cardSpacing) {
            HStack(spacing: 6) {
                if let number {
                    Text("\(number)")
                        .font(.system(size: 9.5, weight: .bold))
                        .foregroundStyle(isRelevant ? Color.white : Color.secondary)
                        .frame(width: 15, height: 15)
                        .background(
                            Circle().fill(isRelevant ? Theme.accent : Color.primary.opacity(0.12))
                        )
                }
                Text(title)
                    .font(Theme.Text.sectionTitle)
                    .foregroundStyle(isRelevant ? Color.primary : Color.secondary)
                Spacer(minLength: 0)
            }

            content
        }
        .padding(Theme.Metrics.cardPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            isRelevant ? Theme.cardFill : Theme.inactiveCardFill,
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cardRadius, style: .continuous)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.Metrics.cardRadius, style: .continuous)
                .strokeBorder(Theme.cardStroke, lineWidth: 1)
        )
        .animation(.easeOut(duration: 0.2), value: isRelevant)
    }
}
