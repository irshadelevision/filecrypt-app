#!/usr/bin/env swift
//
//  make_icon.swift
//  FileCrypt
//
//  Copyright (c) 2026 Irshad Ibrahim
//  SPDX-License-Identifier: MIT
//
//
// Renders the FileCrypt app icon into an .iconset directory.
//
//   swift Scripts/make_icon.swift <output-directory>
//
// Everything is drawn with Core Graphics so the icon is reproducible from
// source with no binary art assets in the repository.

import AppKit
import CoreGraphics
import Foundation

// MARK: - Drawing

/// Draws the icon at a given size. Coordinates are normalised to 0...1 so the
/// same code renders correctly at 16 pt and 1024 pt.
func drawIcon(in context: CGContext, size: CGFloat) {
    let scale = size / 1024.0
    context.saveGState()
    context.scaleBy(x: scale, y: scale)

    // macOS app icons leave a margin around the artwork; the visible shape is
    // about 824/1024 of the canvas.
    let margin: CGFloat = 100
    let side: CGFloat = 1024 - margin * 2
    let body = CGRect(x: margin, y: margin, width: side, height: side)
    let cornerRadius: CGFloat = side * 0.2245

    // --- soft drop shadow ------------------------------------------------
    context.saveGState()
    context.setShadow(
        offset: CGSize(width: 0, height: -18),
        blur: 44,
        color: NSColor.black.withAlphaComponent(0.28).cgColor
    )
    let shadowPath = CGPath(
        roundedRect: body,
        cornerWidth: cornerRadius,
        cornerHeight: cornerRadius,
        transform: nil
    )
    context.addPath(shadowPath)
    context.setFillColor(NSColor.black.cgColor)
    context.fillPath()
    context.restoreGState()

    // --- gradient plate --------------------------------------------------
    context.saveGState()
    context.addPath(shadowPath)
    context.clip()

    let colours = [
        CGColor(red: 0.353, green: 0.573, blue: 1.000, alpha: 1),
        CGColor(red: 0.169, green: 0.290, blue: 0.902, alpha: 1)
    ] as CFArray
    if let gradient = CGGradient(
        colorsSpace: CGColorSpaceCreateDeviceRGB(),
        colors: colours,
        locations: [0, 1]
    ) {
        context.drawLinearGradient(
            gradient,
            start: CGPoint(x: 0, y: 1024),
            end: CGPoint(x: 1024, y: 0),
            options: []
        )
    }

    // Top-edge sheen for a bit of depth.
    if let sheen = CGGradient(
        colorsSpace: CGColorSpaceCreateDeviceRGB(),
        colors: [
            CGColor(red: 1, green: 1, blue: 1, alpha: 0.30),
            CGColor(red: 1, green: 1, blue: 1, alpha: 0.00)
        ] as CFArray,
        locations: [0, 1]
    ) {
        context.drawLinearGradient(
            sheen,
            start: CGPoint(x: 512, y: 924),
            end: CGPoint(x: 512, y: 470),
            options: []
        )
    }
    context.restoreGState()

    // --- padlock ---------------------------------------------------------
    let white = CGColor(red: 1, green: 1, blue: 1, alpha: 1)

    // Shackle: an open arc with a flat bottom, drawn as a stroked circle.
    let shackleRadius: CGFloat = 148
    let shackleCentre = CGPoint(x: 512, y: 606)
    context.setStrokeColor(white)
    context.setLineWidth(76)
    context.setLineCap(.round)
    context.addArc(
        center: shackleCentre,
        radius: shackleRadius,
        startAngle: 0,
        endAngle: .pi,
        // y-up coordinates: "counter-clockwise" draws the upper half.
        clockwise: false
    )
    context.strokePath()

    // Lock body.
    let lockBody = CGRect(x: 292, y: 244, width: 440, height: 362)
    let lockRadius: CGFloat = 78
    context.addPath(
        CGPath(
            roundedRect: lockBody,
            cornerWidth: lockRadius,
            cornerHeight: lockRadius,
            transform: nil
        )
    )
    context.setFillColor(white)
    context.fillPath()

    // Keyhole, punched in the plate colour.
    let plateColour = CGColor(red: 0.222, green: 0.376, blue: 0.945, alpha: 1)
    context.setFillColor(plateColour)

    let keyholeCentre = CGPoint(x: 512, y: 470)
    context.addEllipse(
        in: CGRect(
            x: keyholeCentre.x - 58,
            y: keyholeCentre.y - 58,
            width: 116,
            height: 116
        )
    )
    context.fillPath()

    // Tapered stem below the keyhole circle.
    let stem = CGMutablePath()
    stem.move(to: CGPoint(x: 512 - 30, y: 470))
    stem.addLine(to: CGPoint(x: 512 + 30, y: 470))
    stem.addLine(to: CGPoint(x: 512 + 18, y: 356))
    stem.addLine(to: CGPoint(x: 512 - 18, y: 356))
    stem.closeSubpath()
    context.addPath(stem)
    context.fillPath()

    context.restoreGState()
}

// MARK: - Entry point

let arguments = CommandLine.arguments
guard arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: make_icon.swift <output-directory>\n".utf8))
    exit(2)
}

let outputDirectory = URL(fileURLWithPath: arguments[1])
try? FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

let variants: [(name: String, pixels: Int)] = [
    ("icon_16x16", 16),
    ("icon_16x16@2x", 32),
    ("icon_32x32", 32),
    ("icon_32x32@2x", 64),
    ("icon_128x128", 128),
    ("icon_128x128@2x", 256),
    ("icon_256x256", 256),
    ("icon_256x256@2x", 512),
    ("icon_512x512", 512),
    ("icon_512x512@2x", 1024)
]

for variant in variants {
    let size = variant.pixels
    guard let context = CGContext(
        data: nil,
        width: size,
        height: size,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        FileHandle.standardError.write(Data("could not create a bitmap context\n".utf8))
        exit(1)
    }

    drawIcon(in: context, size: CGFloat(size))

    guard let image = context.makeImage() else {
        FileHandle.standardError.write(Data("could not render the icon\n".utf8))
        exit(1)
    }

    let representation = NSBitmapImageRep(cgImage: image)
    guard let png = representation.representation(using: .png, properties: [:]) else {
        FileHandle.standardError.write(Data("could not encode PNG\n".utf8))
        exit(1)
    }

    let destination = outputDirectory.appendingPathComponent("\(variant.name).png")
    do {
        try png.write(to: destination)
    } catch {
        FileHandle.standardError.write(Data("could not write \(destination.path): \(error)\n".utf8))
        exit(1)
    }
}

print("rendered \(variants.count) icon variants into \(outputDirectory.path)")
