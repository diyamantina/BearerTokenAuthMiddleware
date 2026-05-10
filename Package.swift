// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "BearerTokenAuthMiddleware",
    // Supported platforms per product (CI verifies all of them):
    //
    //   BearerTokenAuthMiddleware       (client; pure OpenAPIRuntime)
    //     - macOS 13+    full swift build + test
    //     - iOS 16+      xcodebuild build verification
    //     - tvOS 16+     xcodebuild build verification
    //     - watchOS 9+   xcodebuild build verification
    //     - Linux        Swift 6.0 container, full swift build + test
    //
    //   BearerTokenAuthServerMiddleware (server; Vapor AsyncMiddleware)
    //     - macOS 13+    full swift build + test
    //     - Linux        Swift 6.0 container, full swift build + test
    //     (Vapor itself does not ship for iOS/tvOS/watchOS — those iOS-style
    //      build jobs only verify the client product compiles. SPM's
    //      `platforms:` array applies package-wide, so the floor is what the
    //      client product needs.)
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9)
    ],
    products: [
        .library(
            name: "BearerTokenAuthMiddleware",
            targets: ["BearerTokenAuthMiddleware"]
        ),
        .library(
            name: "BearerTokenAuthServerMiddleware",
            targets: ["BearerTokenAuthServerMiddleware"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-runtime", from: "1.0.0"),
        .package(url: "https://github.com/vapor/vapor", from: "4.119.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3")
    ],
    targets: [
        .target(
            name: "BearerTokenAuthMiddleware",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime")
            ]
        ),
        .target(
            name: "BearerTokenAuthServerMiddleware",
            dependencies: [
                .product(name: "Vapor", package: "vapor")
            ]
        ),
        .testTarget(
            name: "BearerTokenAuthMiddlewareTests",
            dependencies: [
                "BearerTokenAuthMiddleware",
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime")
            ]
        ),
        .testTarget(
            name: "BearerTokenAuthServerMiddlewareTests",
            dependencies: [
                "BearerTokenAuthServerMiddleware",
                .product(name: "Vapor", package: "vapor"),
                .product(name: "VaporTesting", package: "vapor")
            ]
        )
    ]
)
