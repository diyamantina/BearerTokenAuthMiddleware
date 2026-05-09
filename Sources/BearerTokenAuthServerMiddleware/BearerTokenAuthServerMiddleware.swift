import Vapor

/// Vapor server-side middleware that conditionally enforces bearer token
/// presence based on ``AuthMode``, and propagates the extracted token via
/// ``BearerTokenContext/token`` for downstream handlers.
///
/// Validation strategy (DB session lookup, JWT signature verification, etc.)
/// is intentionally **not** done here — it depends on per-project storage
/// and signing infrastructure, and belongs in the request handler. This
/// middleware only enforces presence.
///
/// Mode behavior:
///
/// - ``AuthMode/none`` — pass through without enforcement. Token is still
///   propagated via `BearerTokenContext.token` if the caller sent one, so
///   handlers may opt into reading it.
/// - ``AuthMode/uuid`` / ``AuthMode/jwt`` — require a bearer token on every
///   request whose path is not in `publicEndpoints` and does not start with
///   any prefix in `publicPathPrefixes`. Missing or oversized tokens are
///   rejected with HTTP 401 (generic message per OWASP, no leak about
///   which mode failed).
public struct BearerTokenAuthServerMiddleware: AsyncMiddleware {
    private let authMode: AuthMode
    private let publicEndpoints: Set<String>
    private let publicPathPrefixes: Set<String>
    private let maxTokenLength: Int

    /// - Parameters:
    ///   - mode: Active authentication mode. Defaults to ``AuthMode/none``
    ///     so the middleware is harmless if installed but unconfigured.
    ///   - publicEndpoints: Exact paths that bypass enforcement (login,
    ///     health probes, etc.). Default empty.
    ///   - publicPathPrefixes: Path prefixes whose subtree bypasses
    ///     enforcement (admin UI mounted under its own auth, static asset
    ///     prefixes). Default empty.
    ///   - maxTokenLength: Reject tokens longer than this to avoid
    ///     allocating unbounded headers. Default `4096`.
    public init(
        mode: AuthMode = .none,
        publicEndpoints: Set<String> = [],
        publicPathPrefixes: Set<String> = [],
        maxTokenLength: Int = 4096
    ) {
        self.authMode = mode
        self.publicEndpoints = publicEndpoints
        self.publicPathPrefixes = publicPathPrefixes
        self.maxTokenLength = maxTokenLength
    }

    public func respond(
        to request: Request,
        chainingTo next: any AsyncResponder
    ) async throws -> Response {
        let token = request.headers.bearerAuthorization?.token

        // .none: passthrough; still propagate token if present.
        if authMode == .none {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        // Public route under any auth mode: passthrough; propagate if present.
        let path = request.url.path
        if publicEndpoints.contains(path)
            || publicPathPrefixes.contains(where: { path.hasPrefix($0) })
        {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        // Protected route under .uuid or .jwt: require token, bound length.
        // Generic message — do not reveal whether the failure was missing,
        // empty, or oversized (OWASP guidance).
        guard let token, !token.isEmpty, token.count <= maxTokenLength else {
            throw Abort(.unauthorized, reason: "Unauthorized")
        }

        return try await BearerTokenContext.$token.withValue(token) {
            try await next.respond(to: request)
        }
    }
}
