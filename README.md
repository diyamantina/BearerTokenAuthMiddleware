# BearerTokenAuthMiddleware

[![Tests](https://github.com/diyamantina/BearerTokenAuthMiddleware/actions/workflows/test.yml/badge.svg)](https://github.com/diyamantina/BearerTokenAuthMiddleware/actions/workflows/test.yml)
![Swift 6.0+](https://img.shields.io/badge/Swift-6.0+-orange.svg)
![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20iOS%20%7C%20Linux-blue.svg)

Bearer-token middleware for Swift OpenAPI clients and Vapor-backed OpenAPI
servers.

The package contains two products:

- `BearerTokenAuthMiddleware`: client-side OpenAPI middleware that stamps
  `Authorization: Bearer <token>` onto generated client requests.
- `BearerTokenAuthServerMiddleware`: Vapor `AsyncMiddleware` that extracts and
  enforces bearer tokens before generated OpenAPI handlers run.

Use the client product in Apple-platform apps, server-to-server clients, or any
target built around `swift-openapi-runtime`. Use the server product when a Vapor
transport needs to protect generated OpenAPI handlers without passing Vapor's
`Request` through every operation.

## Installation

```swift
.package(url: "https://github.com/diyamantina/BearerTokenAuthMiddleware", from: "2.0.0"),
```

```swift
// iOS / macOS app target: client product only.
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "BearerTokenAuthMiddleware", package: "BearerTokenAuthMiddleware"),
    ]
),

// Vapor server target: server product.
.target(
    name: "MyApi",
    dependencies: [
        .product(name: "BearerTokenAuthServerMiddleware", package: "BearerTokenAuthMiddleware"),
        .product(name: "Vapor", package: "vapor"),
    ]
),
```

## Client Quick Start

```swift
import BearerTokenAuthMiddleware
import OpenAPIAsyncHTTPClient

let auth = BearerTokenAuthenticationMiddleware(
    initialToken: nil,
    skipAuthorization: { operationID in
        ["login", "refreshToken", "getHealth"].contains(operationID)
    }
)

let client = Client(
    serverURL: serverURL,
    transport: AsyncHTTPClientTransport(),
    middlewares: [auth]
)

// After login or token refresh:
auth.updateToken(loginResponse.accessToken)

// On logout:
auth.updateToken(nil)
```

The token is stored behind an actor, so it can be updated at runtime without
rebuilding the generated client.

## Server Quick Start

```swift
import BearerTokenAuthServerMiddleware
import Vapor

app.middleware.use(BearerTokenAuthServerMiddleware(mode: .jwt))
```

That single line:

- Exempts the default health, readiness, and metrics endpoints.
- Requires a bearer token everywhere else.
- Runs JWT shape validation by default.
- Stores the extracted token in `BearerTokenContext.token` for downstream
  generated handlers.

Generated handlers can read the token without seeing Vapor's `Request`:

```swift
import BearerTokenAuthServerMiddleware
import Vapor

extension ApiServer {
    public func someProtectedOperation(
        _ input: Operations.SomeOp.Input
    ) async throws -> Operations.SomeOp.Output {
        guard let token = BearerTokenContext.token else {
            throw Abort(.unauthorized)
        }

        // Verify against your session store, JWT verifier, or authorization layer.
    }
}
```

## Server Configuration

```swift
public init(
    mode: AuthMode = .none,
    publicEndpoints: Set<String> = BearerTokenAuthServerMiddleware.defaultPublicEndpoints,
    publicPathPrefixes: Set<String> = [],
    validation: ValidationStrategy = .auto,
    propagateTokenOnPublicRoutes: Bool = false
)
```

| Parameter | Default | Purpose |
|---|---|---|
| `mode` | `.none` | `.none` passes through, `.uuid` expects UUID session tokens, `.jwt` expects JWT-shaped tokens. |
| `publicEndpoints` | health, readiness, metrics paths | Exact paths that bypass enforcement. Pass `[]` to require auth everywhere. |
| `publicPathPrefixes` | `[]` | Boundary-anchored public subtrees. `["/admin"]` matches `/admin` and `/admin/x`, not `/administrator`. |
| `validation` | `.auto` | Chooses `.uuidShape` for `.uuid`, `.jwtShape` for `.jwt`, and `.none` for `.none`. |
| `propagateTokenOnPublicRoutes` | `false` | Keeps `BearerTokenContext.token` empty on public routes unless explicitly opted in. |

## Validation Strategies

The built-in validators are intentionally shape-only:

| Strategy | Behavior |
|---|---|
| `.auto` | Picks from `mode`. |
| `.none` | Only checks that a token is present on protected routes. |
| `.jwtShape` | Requires three non-empty Base64URL segments separated by dots. Does not verify signatures or claims. |
| `.uuidShape` | Requires a canonical UUID string. |
| `.custom(Validator)` | Runs your async validator. Use this for DB session lookup or real JWT verification. |

```swift
let strict = BearerTokenAuthServerMiddleware(
    mode: .jwt,
    validation: .custom { token in
        try await jwtSigners.verify(token, as: AccessTokenPayload.self)
    }
)
```

## Error Model

Server-side failures use typed errors that conform to `AbortError`:

```swift
public enum BearerTokenAuthServerError: Error, AbortError {
    case missingToken
    case invalidToken
}
```

Both return HTTP 401 with the external reason `"Unauthorized"`. Custom
validators may throw any error, such as `Abort(.forbidden)`, and that error
passes through unchanged.

## Task-Local Token

`BearerTokenContext` exposes the token to handlers that do not receive Vapor's
`Request`:

```swift
public enum BearerTokenContext {
    @TaskLocal public static var token: String?
}
```

By default, public routes and `.none` mode do not propagate inbound tokens into
this task-local. Set `propagateTokenOnPublicRoutes: true` only when handlers on
public routes explicitly need to inspect an optional token.

## Architecture

```text
Client side:
  Generated Client
    -> BearerTokenAuthenticationMiddleware
    -> transport

Server side:
  Vapor Request
    -> BearerTokenAuthServerMiddleware
    -> generated OpenAPI handler
       reads BearerTokenContext.token
```

## Companion Packages

- [`ClientIpMiddleware`](https://github.com/diyamantina/ClientIpMiddleware)
  captures client IP and user-agent context for generated OpenAPI handlers.
- [`OpenAPILoggingMiddleware`](https://github.com/diyamantina/OpenAPILoggingMiddleware)
  logs OpenAPI requests and responses with default credential-header redaction.

## Platform Support

The package ships two products with different platform profiles:

| Product | macOS | iOS / tvOS / watchOS | Linux |
|---|---|---|---|
| `BearerTokenAuthMiddleware` | `swift test` | client build verification | `swift test` |
| `BearerTokenAuthServerMiddleware` | `swift test` | Not supported; Vapor is server-only | `swift test` |

Consumers on Apple mobile platforms should depend on the client product only.

## Documentation

DocC is enabled:

```bash
swift package --allow-writing-to-directory ./docs generate-documentation \
    --target BearerTokenAuthServerMiddleware \
    --output-path ./docs/server.doccarchive
```

## Testing

The package ships with **78 tests across 14 suites** covering:

- Client-side header stamping and operation skipping.
- Server modes, default public endpoints, and public prefix matching.
- JWT-shape and UUID-shape validation.
- Custom validators and typed error behavior.
- Task-local propagation and public-route non-propagation.
- Adversarial inputs, large tokens, repeated authorization headers, and
  concurrent request isolation.

Run them with:

```bash
swift test
```

## License

Apache 2.0. See [LICENSE](LICENSE).
