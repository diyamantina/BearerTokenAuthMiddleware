import Foundation
import Vapor

/// Vapor server-side middleware that conditionally enforces bearer token
/// presence based on ``AuthMode``, optionally runs a structural validation
/// strategy against the token, and propagates the token via
/// ``BearerTokenContext/token`` for downstream handlers.
///
/// The middleware does not verify a token's authenticity — DB session
/// lookup, JWT signature verification, expiry checking, etc. require
/// per-project context (the database, the signing key) and stay in the
/// consumer's handlers. Use ``ValidationStrategy/custom(_:)`` to plug
/// project-specific verification in here, or one of the bundled
/// shape-only strategies.
///
/// Mode behavior:
///
/// - ``AuthMode/none`` — pass through without enforcement. Token is still
///   propagated via `BearerTokenContext.token` if the caller sent one,
///   so handlers may opt into reading it. **Validation strategy is not
///   applied in this mode.**
/// - ``AuthMode/uuid`` / ``AuthMode/jwt`` — require a bearer token on
///   every request whose path is not in `publicEndpoints` and is not
///   under any prefix in `publicPathPrefixes`. Missing or oversized
///   tokens throw ``BearerTokenAuthServerError`` (which conforms to
///   `AbortError`, so Vapor translates them to HTTP 401). On a
///   present-and-bounded token, the configured ``ValidationStrategy``
///   runs; if it throws, the error propagates unchanged.
///
/// Path-prefix matching is boundary-anchored: `["/admin"]` and
/// `["/admin/"]` both match `/admin` and `/admin/anything` but neither
/// matches `/administrator`.
public struct BearerTokenAuthServerMiddleware: AsyncMiddleware {

    /// User-supplied closure type for ``ValidationStrategy/custom(_:)``.
    /// Receives the raw bearer token (without the "Bearer " prefix).
    /// Throwing rejects the request; returning normally allows it.
    public typealias Validator = @Sendable (String) async throws -> Void

    /// What to do with a bearer token after presence + length checks pass.
    public enum ValidationStrategy: Sendable {
        /// Don't validate. Middleware only enforces presence + length.
        /// Handlers do whatever validation they need.
        case none

        /// Bundled structural check: token must look like a JWT (three
        /// non-empty Base64URL segments separated by `.`). Does NOT
        /// verify the signature; that needs the signing key.
        case jwtShape

        /// Bundled structural check: token must be a canonical
        /// 8-4-4-4-12 UUID string (case-insensitive).
        case uuidShape

        /// User-supplied validator. Implement DB session lookup,
        /// JWT signature verification, expiry, etc. here.
        case custom(Validator)
    }

    private let authMode: AuthMode
    private let publicEndpoints: Set<String>
    private let normalizedPublicPathPrefixes: Set<String>
    private let maxTokenLength: Int
    private let validation: ValidationStrategy

    /// - Parameters:
    ///   - mode: Active authentication mode. Defaults to ``AuthMode/none``
    ///     so the middleware is harmless if installed but unconfigured.
    ///   - publicEndpoints: Exact paths that bypass enforcement. Default empty.
    ///   - publicPathPrefixes: Path prefixes whose subtree bypasses
    ///     enforcement. Boundary-anchored. Default empty.
    ///   - maxTokenLength: Reject tokens longer than this. Default `4096`.
    ///   - validation: ``ValidationStrategy`` to apply after presence +
    ///     length checks pass. Default ``ValidationStrategy/none`` —
    ///     no extra check beyond presence.
    public init(
        mode: AuthMode = .none,
        publicEndpoints: Set<String> = [],
        publicPathPrefixes: Set<String> = [],
        maxTokenLength: Int = 4096,
        validation: ValidationStrategy = .none
    ) {
        self.authMode = mode
        self.publicEndpoints = publicEndpoints
        self.normalizedPublicPathPrefixes = Set(
            publicPathPrefixes
                .map { $0.hasSuffix("/") ? String($0.dropLast()) : $0 }
                .filter { !$0.isEmpty }
        )
        self.maxTokenLength = maxTokenLength
        self.validation = validation
    }

    public func respond(
        to request: Request,
        chainingTo next: any AsyncResponder
    ) async throws -> Response {
        let token = request.headers.bearerAuthorization?.token

        // .none: passthrough. Validation is not applied.
        if authMode == .none {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        // Public route: passthrough. Validation is not applied.
        let path = request.url.path
        if publicEndpoints.contains(path) || matchesPublicPrefix(path: path) {
            return try await BearerTokenContext.$token.withValue(token) {
                try await next.respond(to: request)
            }
        }

        // Protected route: enforce presence + length, then validate.
        guard let token else {
            throw BearerTokenAuthServerError.missingToken
        }
        guard !token.isEmpty else {
            throw BearerTokenAuthServerError.emptyToken
        }
        guard token.count <= maxTokenLength else {
            throw BearerTokenAuthServerError.oversizedToken(maxLength: maxTokenLength)
        }

        try await applyValidation(to: token)

        return try await BearerTokenContext.$token.withValue(token) {
            try await next.respond(to: request)
        }
    }

    private func applyValidation(to token: String) async throws {
        switch validation {
        case .none:
            return
        case .jwtShape:
            try Self.validateJWTShape(token)
        case .uuidShape:
            try Self.validateUUIDShape(token)
        case .custom(let validator):
            try await validator(token)
        }
    }

    private static let jwtSegmentChars: Set<Character> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )

    private static func validateJWTShape(_ token: String) throws {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw BearerTokenAuthServerError.invalidJWTShape
        }
        for segment in segments {
            guard !segment.isEmpty, segment.allSatisfy({ jwtSegmentChars.contains($0) }) else {
                throw BearerTokenAuthServerError.invalidJWTShape
            }
        }
    }

    private static func validateUUIDShape(_ token: String) throws {
        guard UUID(uuidString: token) != nil else {
            throw BearerTokenAuthServerError.invalidUUIDShape
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
