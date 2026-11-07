// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "VaultSync",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "VaultSync", targets: ["VaultSync"])],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1.git", exact: "0.24.0"),
    ],
    targets: [
        .target(name: "VaultSync", dependencies: [.product(name: "P256K", package: "swift-secp256k1")],
                resources: [.copy("Resources/vault-words.txt")]),
        .testTarget(name: "VaultSyncTests", dependencies: ["VaultSync"],
                    resources: [.copy("Fixtures")]),
    ]
)
