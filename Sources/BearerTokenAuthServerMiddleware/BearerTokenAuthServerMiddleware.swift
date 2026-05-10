import Foundation
import Vapor

/// Vapor server-side middleware that conditionally enforces bearer token
/// presence based on ``AuthMode``, optionally runs a structural validation
/// strategy against the token, and propagates the token via
/// ``BearerTokenContext/token`` for downstream handlers.
///
/// ## Quick start
///
/// Single-line construction picks sensible defaults:
///
///     app.middleware.use(BearerTokenAuthServerMiddleware(mode: .jwt))
///
/// That installs JWT shape validation, exempts the common health/ready
/// endpoints, and rejects any protected-route request without a Bearer
/// header. No further setup required to get a working baseline.
///
/// ## Error model
///
/// - ``AuthMode/none``: never throws. Token (if any) is propagated to
///   ``BearerTokenContext/token`` and the request continues.
/// - ``AuthMode/uuid`` or ``AuthMode/jwt`` on a public route
///   (``publicEndpoints`` exact match, or under ``publicPathPrefixes``):
///   never throws. Same passthrough as ``AuthMode/none``.
/// - ``AuthMode/uuid`` or ``AuthMode/jwt`` on a protected route:
///   - **No usable token** → throws
///     ``BearerTokenAuthServerError/missingToken``. Covers absent
///     `Authorization` header, `Authorization: Bearer ` with empty
///     value, and non-Bearer schemes (`Basic`, `Digest`, garbage).
///   - **Token present, validation strategy rejects it** → throws
///     ``BearerTokenAuthServerError/invalidToken``. (User-supplied
///     ``ValidationStrategy/custom(_:)`` validators may instead throw
///     any `Error`; it propagates unchanged.)
///   - **Token accepted** → handler runs with the token in
///     ``BearerTokenContext/token``.
///
/// ## What the middleware does NOT do
///
/// - **JWT signature verification** — needs the signing key. Use
///   ``ValidationStrategy/custom(_:)`` with JWTKit or similar.
/// - **JWT `exp` / `nbf` / `iat` claim verification** — must happen
///   together with signature verification (otherwise the claims are
///   trivially forgeable). Same place: a `.custom` validator.
/// - **UUID session liveness / expiry** — needs DB access. Same place.
///
/// The bundled ``ValidationStrategy/jwtShape`` is **shape-only** and does
/// not provide any security guarantees beyond "this looks like a JWT."
/// Same for ``ValidationStrategy/uuidShape``.
///
/// ## Path-prefix matching
///
/// Boundary-anchored: `["/admin"]` and `["/admin/"]` both match `/admin`
/// and `/admin/anything` but neither matches `/administrator`.
public struct BearerTokenAuthServerMiddleware: AsyncMiddleware {

    /// User-supplied closure type for ``ValidationStrategy/custom(_:)``.
    /// Receives the raw bearer token (without the "Bearer " prefix).
    /// Throwing rejects the request; returning normally allows it.
    public typealias Validator = @Sendable (String) async throws -> Void

    /// What to do with a bearer token after presence checks pass.
    public enum ValidationStrategy: Sendable {
        /// Auto-pick based on `AuthMode`: `.uuid` → `.uuidShape`,
        /// `.jwt` → `.jwtShape`, `.none` → `.none`.
        case auto

        /// Skip validation entirely. The only thrown case becomes
        /// ``BearerTokenAuthServerError/missingToken``.
        case none
        case jwtShape
        case uuidShape
        case custom(Validator)
    }

    /// Default set of paths exempted from auth enforcement. Health and
    /// readiness probes (Vapor + Kubernetes conventions) plus `/metrics`.
    /// Override by passing your own set; pass an empty set to require
    /// auth on every endpoint.
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

    /// - Parameters:
    ///   - mode: Active authentication mode. Default ``AuthMode/none``.
    ///   - publicEndpoints: Exact paths that bypass enforcement. Defaults
    ///     to ``defaultPublicEndpoints`` (health/ready/metrics).
    ///   - publicPathPrefixes: Path prefixes whose subtree bypasses
    ///     enforcement. Boundary-anchored. Default empty.
    ///   - validation: ``ValidationStrategy`` to apply after presence
    ///     check passes. Default ``ValidationStrategy/auto`` — picks
    ///     based on `mode`. Pass ``ValidationStrategy/none`` to opt out
    ///     of validation entirely even on a non-`.none` mode.
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
        case .auto, .none:           return  // .auto already resolved in init
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
