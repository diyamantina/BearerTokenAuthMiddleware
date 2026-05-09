import Foundation

/// Task-local channel for the bearer token extracted by
/// ``BearerTokenAuthServerMiddleware``. OpenAPI-generated handlers do not
/// receive Vapor's `Request` and cannot read `request.storage`, so the
/// middleware stashes the token here for them.
///
/// Handlers read it with:
///
///     guard let token = BearerTokenContext.token else { ... }
///
/// Vapor handlers can also read this, or use the conventional
/// `request.headers.bearerAuthorization?.token` directly.
public enum BearerTokenContext {
    @TaskLocal public static var token: String?
}
