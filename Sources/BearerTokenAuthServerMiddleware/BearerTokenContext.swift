import Foundation

/// Task-local channel for the bearer token extracted by
/// ``BearerTokenAuthServerMiddleware``.
///
/// ## Overview
///
/// OpenAPI-generated handlers do not receive Vapor's `Request` — they
/// only see the typed `Operations.<OperationName>.Input`. They therefore
/// cannot read the `Authorization` header, `request.storage`, or any
/// other request-scoped Vapor state. The middleware stashes the
/// extracted token here so generated handlers can still authorise the
/// call.
///
/// ## Reading the token
///
///     extension ApiServer {
///         public func someProtectedOperation(
///             _ input: Operations.SomeOp.Input
///         ) async throws -> Operations.SomeOp.Output {
///             guard let token = BearerTokenContext.token else {
///                 // .none mode or public route — your call to allow or reject
///                 throw Abort(.unauthorized)
///             }
///             // ... validate `token` against your session store / signing key,
///             // then continue ...
///         }
///     }
///
/// Conventional Vapor handlers can read this too, or fall back to
/// `request.headers.bearerAuthorization?.token` directly.
///
/// ## Lifetime
///
/// The task-local is set inside `BearerTokenAuthServerMiddleware.respond`
/// via `withValue { ... try await next.respond(to: request) }`, so the
/// value is visible to every async handler executed during that request
/// and is automatically cleared when the closure returns.
///
/// ## Topics
///
/// ### Reading the current token
/// - ``token``
public enum BearerTokenContext {

    /// The bearer token extracted by ``BearerTokenAuthServerMiddleware`` for
    /// the current request. `nil` outside the middleware's scope, or when
    /// no token was present.
    @TaskLocal public static var token: String?
}
