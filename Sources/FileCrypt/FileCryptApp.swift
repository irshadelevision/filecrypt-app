//
//  FileCryptApp.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad
//  SPDX-License-Identifier: MIT
//
import AppKit
import SwiftUI

extension Notification.Name {
    /// Posted by the app delegate when the user drops files on the Dock icon
    /// or opens one through Finder.
    static let fileCryptOpenFile = Notification.Name("com.filecrypt.openFile")
}

final class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Development escape hatch: render the UI to PNG files and exit.
        if DevPreview.isRequested {
            DevPreview.run()
            return
        }

        // Belt and braces: when launched straight from a terminal the process
        // is not always promoted to a regular foreground app on its own.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first else { return }
        NotificationCenter.default.post(name: .fileCryptOpenFile, object: url)
    }
}

@main
struct FileCryptApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 620, height: 720)
        .commands {
            // This is a single-document utility, not a document app.
            CommandGroup(replacing: .newItem) {}
        }
    }
}
