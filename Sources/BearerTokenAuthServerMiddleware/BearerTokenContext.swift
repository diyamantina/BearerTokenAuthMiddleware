import Foundation

/// Task-local channel for the bearer token extracted by ``BearerTokenAuthServerMiddleware``.
///
/// ## Overview
///
/// OpenAPI-generated handlers do not receive Vapor's `Request` — they only see the
/// typed `Operations.<X>.Input`. They therefore cannot read the `Authorization`
/// header, `request.storage`, or any other request-scoped Vapor state. The middleware
/// stashes the extracted token here so generated handlers can still authorise the
/// call.
///
/// Read it from a handler:
///
///     extension ApiServer {
///         public func someProtectedOperation(
///             _ input: Operations.SomeOp.Input
///         ) async throws -> Operations.SomeOp.Output {
///             guard let token = BearerTokenContext.token else {
///                 throw Abort(.unauthorized)
///             }
///             // Validate `token` against your session store / signing key,
///             // then continue.
///         }
///     }
///
/// Conventional Vapor handlers can read this too, or fall back to
/// `request.headers.bearerAuthorization?.token` directly.
///
/// - Note: The task-local is set inside ``BearerTokenAuthServerMiddleware/respond(to:chainingTo:)``
///   via `withValue { ... try await next.respond(to: request) }`, so the value is
///   visible to every async handler executed during that request and is automatically
///   cleared when the closure returns.
///
/// - Important: Task-locals propagate through structured concurrency only. A
///   handler that spawns a `Task.detached { ... }` (or pushes work onto a
///   `DispatchQueue` / explicit `Thread`) **does not** inherit ``token``; the
///   detached scope sees `nil`. Use a non-detached `Task { ... }` if you need
///   the token in async background work the handler kicks off, or capture the
///   value into a local before crossing the boundary:
///
///       let token = BearerTokenContext.token
///       Task.detached { use(token) }
///
/// ## Topics
///
/// ### Reading the current token
/// - ``token``
public enum BearerTokenContext {

    /// The bearer token extracted by ``BearerTokenAuthServerMiddleware`` for the
    /// current request.
    ///
    /// `nil` outside the middleware's scope, or when no token was present.
    @TaskLocal public static var token: String?
}
