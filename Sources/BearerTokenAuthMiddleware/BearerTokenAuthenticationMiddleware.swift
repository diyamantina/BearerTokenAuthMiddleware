import OpenAPIRuntime
import Foundation
import HTTPTypes

// An actor to manage the authentication token state thread-safely.
// This is kept internal to the middleware's implementation.
private actor TokenStorage {
    var token: String?

    func getToken() -> String? { token }
    func setToken(_ newToken: String?) { token = newToken }
}

/// OpenAPI client middleware that stamps `Authorization: Bearer <token>` on every
/// outbound request, with an optional per-operation skip filter.
///
/// ## Overview
///
/// `BearerTokenAuthenticationMiddleware` plugs into the `middlewares:` array of an
/// OpenAPI-generated `Client`. The token is held in an actor so it can be updated at
/// runtime without rebuilding the client — useful when a session refreshes, the user
/// logs out, or an OAuth flow yields a new access token.
///
/// Operations that should not carry the header (typically a `/login`, `/refresh`, or
/// any `security: []` endpoint) opt out via the `skipAuthorization` closure passed to
/// the initializer.
///
///     let auth = BearerTokenAuthenticationMiddleware(
///         initialToken: nil,
///         skipAuthorization: { opID in
///             ["login", "refreshToken", "getHealth"].contains(opID)
///         }
///     )
///
///     let client = Client(
///         serverURL: serverURL,
///         transport: AsyncHTTPClientTransport(),
///         middlewares: [auth]
///     )
///
///     // Later, after a successful login:
///     auth.updateToken(loginResponse.accessToken)
///
/// - Note: ``init(initialToken:skipAuthorization:)`` and ``updateToken(_:)`` schedule
/// the underlying actor write inside an unstructured `Task`, so the write may not
/// have landed by the time you immediately call ``intercept(_:body:baseURL:operationID:next:)``.
/// Tests that construct-then-immediately-intercept should poll until convergence
/// rather than rely on a fixed delay.
///
/// ## Topics
///
/// ### Configuring the middleware
/// - ``init(initialToken:skipAuthorization:)``
///
/// ### Updating the token at runtime
/// - ``updateToken(_:)``
public struct BearerTokenAuthenticationMiddleware {

    private let storage = TokenStorage()
    private let skipAuthorization: @Sendable (String) -> Bool

    /// Creates a new middleware for bearer-token authentication.
    ///
    /// - Parameters:
    ///   - initialToken: The initial bearer token (without the `Bearer ` prefix).
    ///     Pass `nil` if no token is available yet — the middleware will simply not
    ///     stamp a header until you call ``updateToken(_:)``.
    ///   - skipAuthorization: A closure returning `true` if the `Authorization`
    ///     header should be omitted for a specific `operationID`. Defaults to
    ///     applying the header to every operation.
    public init(
        initialToken: String?,
        skipAuthorization: @escaping @Sendable (String) -> Bool = { _ in false }
    ) {
        self.skipAuthorization = skipAuthorization
        Task { [storage] in
            await storage.setToken(initialToken)
        }
    }

    /// Updates the bearer token used by subsequent requests.
    ///
    /// Call this after a login response, a refresh-token exchange, or when the user
    /// logs out (pass `nil` to clear the header).
    ///
    /// - Parameter newToken: The new bearer token (without the `Bearer ` prefix), or
    ///   `nil` to remove the header.
    public func updateToken(_ newToken: String?) {
        Task { [storage] in
            await storage.setToken(newToken)
        }
    }
}

extension BearerTokenAuthenticationMiddleware: ClientMiddleware {
    public func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        if skipAuthorization(operationID) {
            return try await next(request, body, baseURL)
        }

        var modifiedRequest = request
        if let token = await storage.getToken() {
            modifiedRequest.headerFields[.authorization] = "Bearer \(token)"
        }

        return try await next(modifiedRequest, body, baseURL)
    }
}
