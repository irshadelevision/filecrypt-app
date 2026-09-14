//
//  ProgressReporter.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import Foundation

/// Rate-limits progress callbacks so a fast disk does not flood the main queue.
final class ProgressReporter {

    private let callback: ((Double) -> Void)?
    private let phaseCallback: ((FileCipherPhase) -> Void)?
    private var lastReportedTime: CFAbsoluteTime = 0
    private var lastReportedValue: Double = -1

    init(
        callback: ((Double) -> Void)?,
        phaseCallback: ((FileCipherPhase) -> Void)?
    ) {
        self.callback = callback
        self.phaseCallback = phaseCallback
    }

    func phase(_ value: FileCipherPhase) {
        phaseCallback?(value)
    }

    /// Report completion in `0...1`. `force` bypasses the throttle for the
    /// terminal 100 % update.
    func report(_ value: Double, force: Bool = false) {
        guard let callback else { return }
        let clamped = min(max(value, 0), 1)

        if !force {
            if clamped < 1.0, clamped - lastReportedValue < 0.0005 { return }
            let now = CFAbsoluteTimeGetCurrent()
            if now - lastReportedTime < 0.05 { return }
            lastReportedTime = now
        }

        lastReportedValue = clamped
        callback(clamped)
    }
}
