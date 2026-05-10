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
///   request whose path is not in `publicEndpoints` and is not under any
///   path component listed in `publicPathPrefixes`. Missing or oversized
///   tokens are rejected with HTTP 401 (generic message per OWASP, no leak
///   about which mode failed).
///
/// **Path-prefix matching is boundary-anchored.** `["/admin"]` and
/// `["/admin/"]` both match `/admin` and `/admin/anything` but neither
/// matches `/administrator`. Trailing slashes in the configured prefix are
/// normalised away, so the two forms are interchangeable.
public struct BearerTokenAuthServerMiddleware: AsyncMiddleware {
    private let authMode: AuthMode
    private let publicEndpoints: Set<String>
    /// Stored without trailing slash, never empty.
    private let normalizedPublicPathPrefixes: Set<String>
    private let maxTokenLength: Int

    /// - Parameters:
    ///   - mode: Active authentication mode. Defaults to ``AuthMode/none``
    ///     so the middleware is harmless if installed but unconfigured.
    ///   - publicEndpoints: Exact paths that bypass enforcement (login,
    ///     health probes, etc.). Default empty.
    ///   - publicPathPrefixes: Path prefixes whose subtree bypasses
    ///     enforcement. Matched at path-component boundary, so `"/admin"`
    ///     and `"/admin/"` both match `/admin` and `/admin/x` but neither
    ///     matches `/administrator`. Empty prefixes are filtered out at
    ///     init (an empty prefix would match all paths and is almost
    ///     always a configuration mistake).
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
        self.normalizedPublicPathPrefixes = Set(
            publicPathPrefixes
                .map { $0.hasSuffix("/") ? String($0.dropLast()) : $0 }
                .filter { !$0.isEmpty }
        )
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
        if publicEndpoints.contains(path) || matchesPublicPrefix(path: path) {
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

    /// Boundary-anchored prefix match against the normalised set.
    /// Each stored prefix has no trailing slash and is non-empty.
    /// `path` matches `prefix` iff `path == prefix` or `path` starts
    /// with `prefix + "/"`.
    private func matchesPublicPrefix(path: String) -> Bool {
        for prefix in normalizedPublicPathPrefixes {
            if path == prefix || path.hasPrefix(prefix + "/") {
                return true
            }
        }
        return false
    }
}
