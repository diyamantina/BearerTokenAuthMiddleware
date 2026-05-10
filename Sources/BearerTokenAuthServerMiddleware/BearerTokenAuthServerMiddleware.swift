import Foundation
import Vapor

/// Vapor server-side middleware that conditionally enforces bearer token presence
/// based on ``AuthMode``, optionally runs a structural validation strategy against
/// the token, and propagates the token via ``BearerTokenContext/token`` for
/// downstream handlers.
///
/// ## Overview
///
/// Single-line construction picks sensible defaults:
///
///     app.middleware.use(BearerTokenAuthServerMiddleware(mode: .jwt))
///
/// That installs JWT shape validation, exempts the common health/ready endpoints,
/// and rejects any protected-route request without a Bearer header. No further
/// setup is required to get a working baseline.
///
/// In ``AuthMode/none`` the middleware is a passthrough. In ``AuthMode/uuid`` or
/// ``AuthMode/jwt`` on a public route (`publicEndpoints` exact match, or under
/// `publicPathPrefixes`) the middleware also passes through. Everywhere else it
/// requires a bearer token; missing tokens throw
/// ``BearerTokenAuthServerError/missingToken``, the configured ``ValidationStrategy``
/// runs against present tokens and may throw ``BearerTokenAuthServerError/invalidToken``.
///
/// Real signature verification, JWT claim checks, and DB-session lookup belong in
/// ``ValidationStrategy/custom(_:)`` because they need per-project keys / database
/// access; the bundled ``ValidationStrategy/jwtShape`` and
/// ``ValidationStrategy/uuidShape`` are shape-only.
///
/// - Important: Path-prefix matching is boundary-anchored. `["/admin"]` and
///   `["/admin/"]` both match `/admin` and `/admin/anything` but neither matches
///   `/administrator`.
///
/// - Warning: On routes covered by `publicEndpoints` or `publicPathPrefixes`
///   the middleware does not enforce token presence, but it **still**
///   propagates whatever token the caller sent into ``BearerTokenContext/token``
///   for downstream handlers. If a downstream logger captures request headers
///   (e.g. `OpenAPILoggingMiddleware` with a permissive `BodyLoggingPolicy`),
///   valid bearer tokens can land in log files via public-endpoint requests.
///   Mitigations: use `BodyLoggingPolicy.never`, redact the `Authorization`
///   header in a custom `LogHandler`, or skip logging inside public-endpoint
///   handlers entirely.
///
/// ## Topics
///
/// ### Configuring the middleware
/// - ``init(mode:publicEndpoints:publicPathPrefixes:validation:)``
/// - ``defaultPublicEndpoints``
///
/// ### Validation strategies
/// - ``ValidationStrategy``
/// - ``Validator``
///
/// ### Companion types
/// - ``AuthMode``
/// - ``BearerTokenContext``
/// - ``BearerTokenAuthServerError``
public struct BearerTokenAuthServerMiddleware: AsyncMiddleware {

    /// User-supplied closure type for ``ValidationStrategy/custom(_:)``.
    ///
    /// Receives the raw bearer token (without the `Bearer ` prefix). Throwing
    /// rejects the request; returning normally allows it.
    public typealias Validator = @Sendable (String) async throws -> Void

    /// What to do with a bearer token after presence checks pass.
    ///
    /// ## Topics
    ///
    /// ### Strategies
    /// - ``auto``
    /// - ``none``
    /// - ``jwtShape``
    /// - ``uuidShape``
    /// - ``custom(_:)``
    public enum ValidationStrategy: Sendable {

        /// Pick based on ``AuthMode``: `.uuid` → ``uuidShape``,
        /// `.jwt` → ``jwtShape``, `.none` → ``none``. The default.
        case auto

        /// Skip validation entirely.
        ///
        /// The only thrown case becomes ``BearerTokenAuthServerError/missingToken``.
        case none

        /// Token must look like a JWT — three non-empty Base64URL segments separated
        /// by `.`.
        ///
        /// - Note: Does NOT verify the signature; that needs the signing key. Use
        ///   ``custom(_:)`` with a JWT library (JWTKit, jose-swift) for full
        ///   verification including `exp`, `iat`, `nbf`, and audience checks.
        case jwtShape

        /// Token must be a canonical 8-4-4-4-12 UUID string (case-insensitive).
        case uuidShape

        /// User-supplied validator.
        ///
        /// The right place for DB session lookup, JWT signature + claim
        /// verification, expiry checks, etc.
        case custom(Validator)
    }

    /// Default set of paths exempted from auth enforcement.
    ///
    /// Health and readiness probes (Vapor + Kubernetes conventions) plus `/metrics`.
    /// Pass an empty set to ``init(mode:publicEndpoints:publicPathPrefixes:validation:)``
    /// to require auth on every endpoint.
    public static let defaultPublicEndpoints: Set<String> = [
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/metrics"
    ]

    private let authMode: AuthMode
    private let publicEndpoints: Set<String>
    private let normalizedPublicPathPrefixes: Set<String>
    private let validation: ValidationStrategy

    /// Creates a new middleware.
    ///
    /// - Parameters:
    ///   - mode: Active authentication mode. Defaults to ``AuthMode/none``.
    ///   - publicEndpoints: Exact paths that bypass enforcement. Defaults to
    ///     ``defaultPublicEndpoints`` (health/ready/metrics).
    ///   - publicPathPrefixes: Path prefixes whose subtree bypasses enforcement.
    ///     Boundary-anchored. Default empty.
    ///   - validation: ``ValidationStrategy`` to apply after presence check passes.
    ///     Default ``ValidationStrategy/auto``.
    public init(
        mode: AuthMode = .none,
        publicEndpoints: Set<String> = BearerTokenAuthServerMiddleware.defaultPublicEndpoints,
        publicPathPrefixes: Set<String> = [],
        validation: ValidationStrategy = .auto
    ) {
        self.authMode = mode
        self.publicEndpoints = publicEndpoints
        self.normalizedPublicPathPrefixes = Set(
            publicPathPrefixes
                .map { $0.hasSuffix("/") ? String($0.dropLast()) : $0 }
                .filter { !$0.isEmpty }
        )
        switch validation {
        case .auto:
            switch mode {
            case .none: self.validation = .none
            case .uuid: self.validation = .uuidShape
            case .jwt:  self.validation = .jwtShape
            }
        default:
            self.validation = validation
        }
    }

    public func respond(
        to request: Request,
        chainingTo next: any AsyncResponder
    ) async throws -> Response {
        let token = request.headers.bearerAuthorization?.token

        if authMode == .none {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        let path = request.url.path
        if publicEndpoints.contains(path) || matchesPublicPrefix(path: path) {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        guard let token, !token.isEmpty else {
            throw BearerTokenAuthServerError.missingToken
        }

        try await applyValidation(to: token)

        return try await BearerTokenContext.$token.withValue(token) {
            try await next.respond(to: request)
        }
    }

    private func applyValidation(to token: String) async throws {
        switch validation {
        case .auto, .none:           return
        case .jwtShape:              try Self.validateJWTShape(token)
        case .uuidShape:             try Self.validateUUIDShape(token)
        case .custom(let validator): try await validator(token)
        }
    }

    private static let jwtSegmentChars: Set<Character> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )

    private static func validateJWTShape(_ token: String) throws {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw BearerTokenAuthServerError.invalidToken
        }
        for segment in segments {
            guard !segment.isEmpty, segment.allSatisfy({ jwtSegmentChars.contains($0) }) else {
                throw BearerTokenAuthServerError.invalidToken
            }
        }
    }

    private static func validateUUIDShape(_ token: String) throws {
        guard UUID(uuidString: token) != nil else {
            throw BearerTokenAuthServerError.invalidToken
        }
    }

    private func matchesPublicPrefix(path: String) -> Bool {
        for prefix in normalizedPublicPathPrefixes {
            if path == prefix || path.hasPrefix(prefix + "/") {
                return true
            }
        }
        return false
    }
}
