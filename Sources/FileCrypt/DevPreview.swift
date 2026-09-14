//
//  DevPreview.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import AppKit
import FileCryptCore
import Foundation
import SwiftUI

/// Development-only offline renderer.
///
/// macOS refuses screen capture to unattended processes, so this gives a
/// deterministic way to *look* at the interface:
///
///     FileCrypt --render-preview <directory>
///
/// It writes `encrypt.png`, `encrypt-filled.png`, `decrypt.png` and
/// `success.png` and exits. Nothing here runs during normal use; the flag is
/// checked once at launch.
@MainActor
enum DevPreview {

    static var isRequested: Bool {
        CommandLine.arguments.contains("--render-preview")
    }

    static func run() {
        let arguments = CommandLine.arguments
        guard let flagIndex = arguments.firstIndex(of: "--render-preview"),
              flagIndex + 1 < arguments.count else {
            FileHandle.standardError.write(Data("usage: FileCrypt --render-preview <directory>\n".utf8))
            exit(2)
        }

        // A window can only be created once AppKit is up; the preview path runs
        // from `applicationDidFinishLaunching`, so all that is left is to keep
        // the process out of the Dock.
        NSApp.setActivationPolicy(.accessory)

        let directory = URL(fileURLWithPath: arguments[flagIndex + 1])
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        // The machine's appearance decides what the previews look like. Pin it
        // to light so two runs of this tool are comparable, and so the output
        // matches what most users of this kind of utility will see.
        for domain in [Bundle.main.bundleIdentifier, "com.filecrypt.FileCrypt"].compactMap({ $0 }) {
            UserDefaults.standard.removePersistentDomain(forName: domain)
        }
        // `--dark` renders the other appearance, so both can be reviewed.
        let wantsDark = arguments.contains("--dark")
        NSApp.appearance = NSAppearance(named: wantsDark ? .darkAqua : .aqua)

        // A scratch file so the "file chosen" states are realistic.
        let scratch = directory.appendingPathComponent("Quarterly Report.pdf")
        try? Data(repeating: 0x41, count: 2_400_000).write(to: scratch)

        let encryptedFixture = directory.appendingPathComponent("Quarterly Report.pdf.fcrypt")
        try? makeEncryptedFixture(at: encryptedFixture)

        render(model: makeModel(file: nil, password: "", confirm: ""), to: directory.appendingPathComponent("encrypt.png"))
        render(model: makeModel(file: scratch, password: "Tr0ub4dor&3xample", confirm: "Tr0ub4dor&3xample"), to: directory.appendingPathComponent("encrypt-filled.png"))

        let weak = makeModel(file: scratch, password: "password", confirm: "password")
        render(model: weak, to: directory.appendingPathComponent("encrypt-weak.png"))

        let decrypt = makeModel(file: encryptedFixture, password: "Tr0ub4dor&3xample", confirm: "")
        decrypt.mode = .decrypt
        render(model: decrypt, to: directory.appendingPathComponent("decrypt.png"))

        let success = makeModel(file: encryptedFixture, password: "", confirm: "")
        success.mode = .decrypt
        render(model: success, to: directory.appendingPathComponent("quiescent.png"))

        // The state right after pressing Generate: revealed password, the
        // "save it now" banner, and the Copy button.
        let generated = makeModel(file: scratch, password: "", confirm: "")
        generated.generatePassword()
        render(model: generated, to: directory.appendingPathComponent("encrypt-generated.png"))

        try? FileManager.default.removeItem(at: scratch)
        try? FileManager.default.removeItem(at: encryptedFixture)

        FileHandle.standardError.write(Data("rendered previews into \(directory.path)\n".utf8))
        exit(0)
    }

    private static func makeEncryptedFixture(at url: URL) throws {
        let source = url.deletingLastPathComponent().appendingPathComponent("fixture-source.bin")
        try Data(repeating: 0x42, count: 4_096).write(to: source)
        try FileCipher.encryptFile(
            at: source,
            to: url,
            password: "fixture",
            options: EncryptionOptions(chunkSize: 4_096, memoryKiB: 1_024, timeCost: 1, parallelism: 1)
        )
        try? FileManager.default.removeItem(at: source)
    }

    private static func makeModel(file: URL?, password: String, confirm: String) -> AppModel {
        let model = AppModel()
        if let file {
            model.setInputFile(file)
        }
        model.password = password
        model.confirmPassword = confirm
        return model
    }

    private static func render(model: AppModel, to url: URL) {
        let width: CGFloat = 620

        // Render through a real `NSHostingView` rather than SwiftUI's
        // `ImageRenderer`. ImageRenderer uses its own rasteriser, which cannot
        // draw AppKit-backed controls — text fields, segmented pickers and the
        // drag-and-drop zone come out as yellow "unrenderable" blocks. Hosting
        // the view in a window and asking AppKit to cache its display goes
        // through exactly the drawing path the user sees.
        let hosting = NSHostingView(rootView: ContentView(model: model))
        hosting.frame = NSRect(x: 0, y: 0, width: width, height: 400)

        let window = NSWindow(
            contentRect: hosting.frame,
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hosting

        // AppKit draws controls in a muted "inactive window" style unless the
        // window is key, which would make every preview look washed out and
        // hide whether the accent colour is applied. The window flashes on
        // screen for a moment; acceptable for a development-only tool.
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        hosting.layoutSubtreeIfNeeded()

        // Ask SwiftUI for its ideal height, then size the window to match.
        let height = max(hosting.fittingSize.height, 200)
        hosting.frame = NSRect(x: 0, y: 0, width: width, height: height)
        window.setContentSize(NSSize(width: width, height: height))
        window.layoutIfNeeded()
        hosting.layoutSubtreeIfNeeded()
        hosting.displayIfNeeded()

        guard let representation = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else {
            FileHandle.standardError.write(
                Data("could not allocate a bitmap for \(url.lastPathComponent)\n".utf8)
            )
            return
        }
        hosting.cacheDisplay(in: hosting.bounds, to: representation)

        guard let png = representation.representation(using: .png, properties: [:]) else {
            FileHandle.standardError.write(Data("could not encode \(url.lastPathComponent)\n".utf8))
            return
        }

        do {
            try png.write(to: url)
        } catch {
            FileHandle.standardError.write(Data("could not write \(url.path): \(error)\n".utf8))
        }
    }
}
