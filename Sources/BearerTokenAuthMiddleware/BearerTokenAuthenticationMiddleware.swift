import OpenAPIRuntime
import Foundation
import HTTPTypes

// Thread-safe, synchronous token storage. A lock-protected class instead of an actor:
// the previous actor-based storage required `updateToken(_:)` and `init` to schedule
// their writes inside an unstructured `Task` (since neither is `async`), so a token set
// and then immediately used by the very next request could race — the write had no
// guaranteed happens-before relationship with a subsequent `intercept` call. A plain lock
// makes both the write and the read ordinary synchronous calls, so there is no window at
// all: by the time `updateToken(_:)` returns, the new value is visible to every later
// caller, actor hop or not.
private final class TokenStorage: @unchecked Sendable {
    private let lock = NSLock()
    private var _token: String?

    var token: String? {
        get { lock.withLock { _token } }
        set { lock.withLock { _token = newValue } }
    }
}

/// OpenAPI client middleware that stamps `Authorization: Bearer <token>` on every
/// outbound request, with an optional per-operation skip filter.
///
/// ## Overview
///
/// `BearerTokenAuthenticationMiddleware` plugs into the `middlewares:` array of an
/// OpenAPI-generated `Client`. The token is held in a lock-protected store so it can be
/// updated at runtime without rebuilding the client — useful when a session refreshes, the
/// user logs out, or an OAuth flow yields a new access token.
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
/// - Note: both ``init(initialToken:skipAuthorization:)`` and ``updateToken(_:)`` write the
/// token synchronously — by the time either call returns, the new value is visible to any
/// subsequent ``intercept(_:body:baseURL:operationID:next:)`` call, including one made
/// immediately afterward. No polling or delay is needed.
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
        storage.token = initialToken
    }

    /// Updates the bearer token used by subsequent requests.
    ///
    /// Call this after a login response, a refresh-token exchange, or when the user
    /// logs out (pass `nil` to clear the header). The write is synchronous and visible
    /// to any request made after this call returns, with no race window.
    ///
    /// - Parameter newToken: The new bearer token (without the `Bearer ` prefix), or
    ///   `nil` to remove the header.
    public func updateToken(_ newToken: String?) {
        storage.token = newToken
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
        if let token = storage.token {
            modifiedRequest.headerFields[.authorization] = "Bearer \(token)"
        }

        return try await next(modifiedRequest, body, baseURL)
    }
}
