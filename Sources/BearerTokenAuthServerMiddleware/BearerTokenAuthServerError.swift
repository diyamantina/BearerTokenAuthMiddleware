import Vapor

/// Typed errors thrown by ``BearerTokenAuthServerMiddleware``. All cases
/// map to HTTP 401 with a generic "Unauthorized" reason (OWASP guidance:
/// don't leak which sub-failure tripped) — but tests, instrumentation,
/// and structured logging can still pattern-match on the typed case.
///
/// Conforming to `AbortError` lets Vapor translate any thrown case into
/// the correct HTTP response automatically.
public enum BearerTokenAuthServerError: Error, AbortError, Equatable {

    /// No `Authorization: Bearer ...` header on a protected route.
    case missingToken

    /// `Authorization: Bearer` was present but the token portion was empty.
    case emptyToken

    /// Token exceeded the configured `maxTokenLength`.
    case oversizedToken(maxLength: Int)

    /// Selected ``ValidationStrategy/jwtShape`` and the token did not
    /// match the JWT structural shape.
    case invalidJWTShape

    /// Selected ``ValidationStrategy/uuidShape`` and the token did not
    /// match the canonical UUID string format.
    case invalidUUIDShape

    public var status: HTTPResponseStatus { .unauthorized }

    /// All cases surface the same external reason. Internal differentiation
    /// is for diagnostics, not for clients (per OWASP).
    public var reason: String { "Unauthorized" }
}
