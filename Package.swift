// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "BearerTokenAuthMiddleware",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
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
        .package(url: "https://github.com/vapor/vapor", from: "4.119.0")
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
