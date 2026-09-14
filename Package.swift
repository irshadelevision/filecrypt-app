// swift-tools-version: 6.0
import PackageDescription

// The whole project is deliberately dependency-free: it only uses CryptoKit,
// CommonCrypto and Foundation, all of which ship with macOS.
let sharedSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v5)
]

let package = Package(
    name: "FileCrypt",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "FileCryptCore", targets: ["FileCryptCore"]),
        .executable(name: "FileCrypt", targets: ["FileCrypt"]),
        .executable(name: "fcrypt", targets: ["fcrypt"])
    ],
    targets: [
        // The PHC reference Argon2 implementation, vendored so the package
        // still needs no network access or third-party dependency resolution.
        // Hand-rolling a memory-hard KDF would be reckless; this is the same
        // code that won the Password Hashing Competition and that every other
        // Argon2 implementation is checked against.
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["LICENSE"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("blake2")
            ]
        ),
        .target(
            name: "FileCryptCore",
            dependencies: ["CArgon2"],
            swiftSettings: sharedSwiftSettings
        ),
        .executableTarget(
            name: "FileCrypt",
            dependencies: ["FileCryptCore"],
            swiftSettings: sharedSwiftSettings
        ),
        .executableTarget(
            name: "fcrypt",
            dependencies: ["FileCryptCore"],
            swiftSettings: sharedSwiftSettings
        ),
        .testTarget(
            name: "FileCryptCoreTests",
            dependencies: ["FileCryptCore"],
            swiftSettings: sharedSwiftSettings
        ),
        .testTarget(
            name: "FileCryptAppTests",
            dependencies: ["FileCrypt"],
            swiftSettings: sharedSwiftSettings
        )
    ]
)
