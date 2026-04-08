---
title: Building a Concurrency-Safe Bearer Token Middleware for Swift OpenAPI Clients
subtitle: "Elegant, Thread-Safe Authentication for OpenAPI Runtime"
date: 2025-10-19
tags: [Swift, OpenAPI, Authentication, Middleware, Concurrency, OpenSource, Architecture, iOS, macOS]
published: true
image: /images/auth/bearer-token-middleware.jpg
---

# Building a Concurrency-Safe Bearer Token Middleware for Swift OpenAPI Clients

Authentication is one of those things that every API client needs, yet implementing it cleanly and safely can be surprisingly tricky—especially in Swift's modern concurrency world. Today, I'm sharing a lightweight middleware solution that handles Bearer token authentication for OpenAPI-generated Swift clients in a thread-safe, composable way.

## The Problem

When working with OpenAPI Runtime in Swift, you often need to:

- Inject an `Authorization: Bearer <token>` header into API requests
- Update tokens dynamically (after login, token refresh, etc.)
- Skip authentication for certain endpoints (like login or public routes)
- Ensure thread-safety in concurrent environments

While this sounds straightforward, getting it right with Swift 6's strict concurrency checking requires careful design. You need proper actor isolation, Sendable conformance, and a clean API that doesn't fight the type system.

## The Solution: BearerTokenAuthenticationMiddleware

I built `BearerTokenAuthenticationMiddleware`—a minimal, zero-dependency package that solves these problems elegantly. Here's what makes it special:

### 1. Actor-Isolated Token Storage

The heart of the middleware is a private `TokenStorage` actor that manages the authentication token:

```swift
private actor TokenStorage {
    var token: String?

    func getToken() -> String? {
        token
    }

    func setToken(_ newToken: String?) {
        token = newToken
    }
}
```

This ensures that token reads and writes are **never concurrent**, eliminating race conditions completely. The actor isolation guarantee means you can safely update tokens from anywhere in your app without worrying about data races.

### 2. Clean, Composable API

Setting up the middleware is straightforward:

```swift
import OpenAPIRuntime
import BearerTokenAuthMiddleware

let authMiddleware = BearerTokenAuthenticationMiddleware(
    initialToken: "my-secret-token"
)

let client = Client(
    serverURL: URL(string: "https://api.example.com")!,
    transport: AsyncHTTPClientTransport(),
    middlewares: [authMiddleware]
)
```

Every request now automatically includes `Authorization: Bearer my-secret-token`.

### 3. Selective Authentication

Not all endpoints need authentication. Public endpoints like `/login`, `/register`, or `/healthcheck` shouldn't send tokens. The middleware supports this via a `skipAuthorization` closure:

```swift
let authMiddleware = BearerTokenAuthenticationMiddleware(
    initialToken: "my-token",
    skipAuthorization: { operationID in
        ["login", "register", "healthcheck"].contains(operationID)
    }
)
```

The closure receives the `operationID` from your OpenAPI spec and returns `true` to skip the header injection. Simple, flexible, and type-safe.

### 4. Dynamic Token Updates

Tokens expire. Users log out and back in. The middleware handles runtime token updates safely:

```swift
await authMiddleware.updateToken("new-access-token")
```

Because the storage is actor-isolated, this update is guaranteed to be thread-safe. The next request will automatically use the new token.

## How It Works Under the Hood

The middleware conforms to OpenAPIRuntime's `ClientMiddleware` protocol and intercepts every outgoing request:

```swift
extension BearerTokenAuthenticationMiddleware: ClientMiddleware {
    public func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        // Skip if the operation is public
        if skipAuthorization(operationID) {
            return try await next(request, body, baseURL)
        }

        var modifiedRequest = request

        // Inject the Bearer token
        if let token = await storage.getToken() {
            modifiedRequest.headerFields[.authorization] = "Bearer \(token)"
        }

        return try await next(modifiedRequest, body, baseURL)
    }
}
```

The flow is:

1. Check if this operation should skip authentication
2. If not, retrieve the token from actor-isolated storage
3. Inject it into the `Authorization` header with the `Bearer` prefix
4. Pass the modified request down the middleware chain

## Real-World Integration

Here's how it fits into a production API client alongside other middlewares like logging:

```swift
import OpenAPIRuntime
import OpenAPIAsyncHTTPClient
import OpenAPILoggingMiddleware
import BearerTokenAuthMiddleware

public actor ApiClient {
    public var client: Client

    public init(environment: ServerEnvironment) async throws {
        let authMiddleware = BearerTokenAuthenticationMiddleware(
            initialToken: await ApiClientState.shared.token,
            skipAuthorization: { operationID in
                await ApiClientState.shared.isPublicOperation(operationID)
            }
        )

        let loggingMiddleware = LoggingMiddleware(
            appName: "MyAPI",
            logPrefix: "🚚 APIClient: "
        )

        let serverURL = try environment.getURL()
        client = Client(
            serverURL: serverURL,
            transport: AsyncHTTPClientTransport(),
            middlewares: [loggingMiddleware, authMiddleware]
        )
    }
}
```

Middlewares compose naturally—each one does its job and passes control to the next. Logging, authentication, error correction, and custom logic all work together seamlessly.

## Why This Design?

You might wonder: why not just use a simple `var token: String?` property with a lock? A few reasons:

1. **Swift 6 Concurrency**: Actors provide compile-time guarantees that manual locks can't. The compiler ensures you can't accidentally bypass the isolation.

2. **Sendable Conformance**: The middleware struct itself can be safely shared across concurrency domains because the mutable state is isolated in an actor.

3. **Ergonomics**: No need to manually manage locks, semaphores, or dispatch queues. The actor model handles it all.

4. **Future-Proof**: As Swift's concurrency story evolves, actor-based code will continue to work well with new features and improvements.

## Installation

Add the package to your `Package.swift`:

```swift
.package(
    url: "https://github.com/mihaelamj/BearerTokenAuthMiddleware.git",
    from: "1.0.0"
)
```

Then add it to your target dependencies:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(
            name: "BearerTokenAuthMiddleware",
            package: "BearerTokenAuthMiddleware"
        )
    ]
)
```

## Wrapping Up

Building authentication middleware might seem like boilerplate, but doing it right—especially with modern Swift concurrency—requires thoughtful design. `BearerTokenAuthenticationMiddleware` provides:

- Thread-safe token management via actors
- Selective authentication with operation-level control
- Dynamic token updates
- Zero dependencies
- Clean composition with other middlewares

If you're building Swift clients for OpenAPI specs and need a robust, concurrency-safe way to handle Bearer tokens, give it a try. The source code is available on [GitHub](https://github.com/mihaelamj/BearerTokenAuthMiddleware), and I'd love to hear your feedback.

Happy coding!

---

**Tech Stack**: Swift 6.0+, OpenAPIRuntime, Swift Concurrency
**License**: MIT
**Repository**: [github.com/mihaelamj/BearerTokenAuthMiddleware](https://github.com/mihaelamj/BearerTokenAuthMiddleware)
