# BearerTokenAuthMiddleware

![Swift 6.0+](https://img.shields.io/badge/Swift-6.0+-orange.svg)
![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20iOS%20%7C%20Linux-blue.svg)

Two complementary middlewares for Swift services that speak OpenAPI:

- **`BearerTokenAuthMiddleware`** — client-side. Stamps `Authorization: Bearer <token>` on outbound OpenAPI requests, with per-operation skip filtering. Pure `OpenAPIRuntime`, safe on iOS.
- **`BearerTokenAuthServerMiddleware`** — server-side. Vapor `AsyncMiddleware` that conditionally enforces token presence, optionally runs structural validation (JWT shape / UUID shape / custom closure), and propagates the token via a `TaskLocal` so OpenAPI-generated handlers (which never see Vapor's `Request`) can read it.

Both products live in the same package; pick the one(s) you need per target.

## Installation

```swift
.package(url: "https://github.com/mihaelamj/BearerTokenAuthMiddleware", from: "2.0.0"),
```

```swift
// iOS / macOS app target — only needs the client product
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "BearerTokenAuthMiddleware", package: "BearerTokenAuthMiddleware"),
    ]
),

// Vapor server target — needs the server product
.target(
    name: "MyApi",
    dependencies: [
        .product(name: "BearerTokenAuthServerMiddleware", package: "BearerTokenAuthMiddleware"),
        .product(name: "Vapor", package: "vapor"),
    ]
),
```

## Quick start

### Client (iOS / macOS / server-to-server)

```swift
import BearerTokenAuthMiddleware
import OpenAPIAsyncHTTPClient

let auth = BearerTokenAuthenticationMiddleware(
    initialToken: nil,
    skipAuthorization: { opID in
        ["login", "refreshToken", "getHealth"].contains(opID)
    }
)

let client = Client(
    serverURL: serverURL,
    transport: AsyncHTTPClientTransport(),
    middlewares: [auth]
)

// Later, after a successful login:
auth.updateToken(loginResponse.accessToken)
```

### Server (Vapor)

```swift
import BearerTokenAuthServerMiddleware
import Vapor

// One-liner: JWT shape validation + health-endpoint exemption + bearer enforcement
app.middleware.use(BearerTokenAuthServerMiddleware(mode: .jwt))
```

That's a fully-configured middleware. The `validation: .auto` default resolves to `.jwtShape`, the default `publicEndpoints` exempt `/health`, `/healthz`, `/ready`, `/readyz`, `/metrics`, and any other route that lacks a Bearer header gets a 401.

OpenAPI-generated handlers can read the extracted token:

```swift
import BearerTokenAuthServerMiddleware

extension ApiServer {
    public func someProtectedOperation(
        _ input: Operations.SomeOp.Input
    ) async throws -> Operations.SomeOp.Output {
        guard let token = BearerTokenContext.token else {
            throw Abort(.unauthorized)
        }
        // Validate `token` against your session store / signing key, then continue.
    }
}
```

## Server-side configuration

```swift
public init(
    mode: AuthMode = .none,
    publicEndpoints: Set<String> = BearerTokenAuthServerMiddleware.defaultPublicEndpoints,
    publicPathPrefixes: Set<String> = [],
    validation: ValidationStrategy = .auto,
    propagateTokenOnPublicRoutes: Bool = false
)
```

| Parameter | Default | Notes |
|---|---|---|
| `mode` | `.none` | Use `.uuid` for DB-session tokens, `.jwt` for signed JWTs. `.none` makes the middleware a passthrough. |
| `publicEndpoints` | `["/health", "/healthz", "/ready", "/readyz", "/metrics"]` | Exact-path bypass list. Pass `[]` to require auth on every endpoint. |
| `publicPathPrefixes` | `[]` | Boundary-anchored prefix matching. `["/admin"]` matches `/admin` and `/admin/x` but **not** `/administrator`. Trailing slash is normalised. |
| `validation` | `.auto` | Resolves to `.uuidShape` for `.uuid`, `.jwtShape` for `.jwt`, `.none` for `.none`. Override with any explicit case. |
| `propagateTokenOnPublicRoutes` | `false` | When the request bypasses enforcement (a public-endpoint or public-prefix match, or `.none` mode), keep `BearerTokenContext.token` `nil` so handlers and downstream loggers cannot accidentally see a token the operator declared they shouldn't. Set to `true` to surface the inbound token (pre-2.x behaviour). |

### Validation strategies

| `ValidationStrategy` | Behaviour |
|---|---|
| `.auto` | Picks based on `mode`. The default. |
| `.none` | Skip validation entirely. The only thrown case is `BearerTokenAuthServerError.missingToken`. |
| `.jwtShape` | Token must be three non-empty Base64URL segments separated by `.`. **Does not verify the signature.** |
| `.uuidShape` | Token must be a canonical 8-4-4-4-12 UUID string (case-insensitive). |
| `.custom(Validator)` | User-supplied async closure. Throw to reject; return to allow. The right place for DB session lookup, JWT signature + claim verification, etc. |

## Error model

Two typed cases, both conform to `AbortError` so Vapor returns HTTP 401 with reason `"Unauthorized"` (OWASP — same external message regardless of which sub-failure tripped):

```swift
public enum BearerTokenAuthServerError: Error, AbortError {
    case missingToken    // no usable bearer token on a protected route
    case invalidToken    // present but the validation strategy rejected it
}
```

| Caller sent | Thrown |
|---|---|
| nothing on `Authorization` | `.missingToken` |
| `Authorization: Bearer ` (empty value) | `.missingToken` |
| `Authorization: Basic ...` / Digest / etc. | `.missingToken` |
| `Authorization: Bearer <bad-shape>` | `.invalidToken` |
| `Authorization: Bearer <good-shape>` | (no error) |

A `.custom` validator may throw any `Error` — for example `Abort(.forbidden)` — and that error propagates unchanged through the middleware, so callers can surface different HTTP statuses.

## What the middleware does NOT do

The bundled validators are **shape-only**. The middleware deliberately does not:

- Verify a JWT's signature (needs the signing key — use `.custom` with `JWTKit` or similar).
- Check `exp`, `nbf`, or `iat` claims (must happen alongside signature verification — same place).
- Look up UUID sessions in a database (needs DB access — same place).

These all live in `.custom(Validator)` because they need per-project context the middleware cannot have.

```swift
let strict = BearerTokenAuthServerMiddleware(
    mode: .jwt,
    validation: .custom { token in
        // your JWTKit verifier here — verifies signature, exp, iss, aud
        try await jwtSigners.verify(token, as: AccessTokenPayload.self)
    }
)
```

## Companion: `AuthMode`

Shared between client and server so both sides agree on what the token *is*:

```swift
public enum AuthMode: String, Sendable {
    case none   // no auth headers
    case uuid   // UUID session tokens, validated against your session store
    case jwt    // signed JWTs, verified against your signing key
}
```

Mixing modes (`.none` client talking to `.uuid` server, for example) fails closed — the server returns 401 because the client never sent a token.

## Companion: `BearerTokenContext`

A `@TaskLocal` for handlers that don't see Vapor's `Request`:

```swift
public enum BearerTokenContext {
    @TaskLocal public static var token: String?
}
```

The server middleware sets this inside its `withValue` block so every async handler executed during the request can read `BearerTokenContext.token`.

## Documentation

DocC is enabled. Generate the archive locally with:

```bash
swift package --allow-writing-to-directory ./docs generate-documentation \
    --target BearerTokenAuthServerMiddleware \
    --output-path ./docs/server.doccarchive
```

Open the archive in Xcode (or use `xcrun docc preview-documentation`) to browse types, see Topics groupings, and follow cross-references between `BearerTokenAuthServerMiddleware` ↔ `AuthMode` ↔ `BearerTokenContext` ↔ `BearerTokenAuthServerError`.

## Architecture

```
Client side (OpenAPI):
  Request → BearerTokenAuthenticationMiddleware → next → Server
            (stamps Authorization)

Server side (Vapor):
  Request → ClientIpMiddleware (optional, separate package)
          → BearerTokenAuthServerMiddleware
            (extracts token, enforces presence, runs ValidationStrategy,
             stashes on BearerTokenContext.token via TaskLocal)
          → OpenAPI handlers (read BearerTokenContext.token to validate
            against DB / signing key)
```

## Testing

The package ships **64 tests across 13 suites**:

| Area | Tests |
|---|---|
| Client middleware | 8 |
| Server core (modes, defaults, propagation, public-route opt-in) | 19 |
| Path-prefix boundary matching | 5 |
| Path-prefix init normalization | 1 |
| Non-Bearer Authorization schemes | 3 |
| HTTP methods (POST/PUT/PATCH/DELETE) | 4 |
| Auto-picked validation strategy | 3 |
| `.custom(Validator)` | 5 |
| `.jwtShape` | 4 |
| `.uuidShape` | 3 |
| Typed errors | 5 |
| `AuthMode` | 3 |
| `BearerTokenContext` | 4 |

Run them with `swift test`.

CI runs the suite on macOS and on Linux (Swift 6.0 container).

## License

Apache 2.0 — see [LICENSE](LICENSE).
