//
//  Theme.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
import FileCryptCore
import SwiftUI

/// Design tokens for the window.
///
/// Everything visual is named here rather than written inline, so the interface
/// stays coherent when a value changes and so there is one place to look when
/// asking "what does this app consider a corner radius?".
enum Theme {

    // MARK: - Colour

    /// The single accent colour. Deliberately close to the system blue but
    /// slightly deeper, so the app reads as intentional rather than unthemed.
    static let accent = Color(red: 0.24, green: 0.42, blue: 0.96)

    static var accentGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(red: 0.33, green: 0.55, blue: 1.00),
                Color(red: 0.19, green: 0.33, blue: 0.88)
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    static let accentSoft = accent.opacity(0.10)

    // MARK: - Surfaces

    static let cardFill = Color(nsColor: .controlBackgroundColor)
    static let cardStroke = Color.primary.opacity(0.07)
    /// Cards that are not yet actionable recede rather than disappear.
    static let inactiveCardFill = Color(nsColor: .controlBackgroundColor).opacity(0.5)

    static let dropFill = Color.primary.opacity(0.03)
    static let dropStroke = Color.primary.opacity(0.14)
    static let meterTrack = Color.primary.opacity(0.09)

    static var windowBackground: LinearGradient {
        LinearGradient(
            colors: [
                Color(nsColor: .windowBackgroundColor),
                Color(nsColor: .windowBackgroundColor)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    // MARK: - Metrics

    enum Metrics {
        static let windowWidth: CGFloat = 620
        static let contentPadding: CGFloat = 20
        static let cardPadding: CGFloat = 14
        static let cardSpacing: CGFloat = 10
        static let sectionSpacing: CGFloat = 14
        static let cardRadius: CGFloat = 12
        static let controlRadius: CGFloat = 7
        static let dropZoneRadius: CGFloat = 10
        static let dropZoneHeight: CGFloat = 88
    }

    // MARK: - Type

    enum Text {
        static let title = Font.system(size: 19, weight: .semibold)
        static let subtitle = Font.system(size: 11.5)
        static let sectionTitle = Font.system(size: 10.5, weight: .semibold)
        static let body = Font.system(size: 12.5)
        static let bodyMedium = Font.system(size: 12.5, weight: .medium)
        static let caption = Font.system(size: 10.5)
        static let mono = Font.system(size: 12, design: .monospaced)
    }

    // MARK: - Semantic colour

    static func strengthColor(_ strength: PasswordStrength) -> Color {
        switch strength {
        case .veryWeak: return Color(red: 0.85, green: 0.22, blue: 0.22)
        case .weak: return Color(red: 0.90, green: 0.45, blue: 0.13)
        case .fair: return Color(red: 0.85, green: 0.65, blue: 0.10)
        case .strong: return Color(red: 0.24, green: 0.65, blue: 0.34)
        case .veryStrong: return Color(red: 0.13, green: 0.55, blue: 0.40)
        }
    }
}
