import Vapor

/// Typed errors thrown by ``BearerTokenAuthServerMiddleware``. Two cases:
///
/// - ``missingToken`` — the request had no usable bearer token on a
///   protected route. Covers: no `Authorization` header, `Authorization:
///   Bearer ` with an empty value, and non-Bearer schemes (`Basic ...`,
///   `Digest ...`, garbage).
/// - ``invalidToken`` — a token was present but the configured
///   ``BearerTokenAuthServerMiddleware/ValidationStrategy`` rejected it
///   (wrong shape, signature mismatch from a `.custom` validator, etc.).
///
/// Both cases conform to `AbortError` so Vapor translates them to HTTP
/// 401 with a generic "Unauthorized" reason (OWASP — same external
/// message regardless of which sub-failure tripped). Tests and
/// instrumentation pattern-match the typed case for richer signal.
public enum BearerTokenAuthServerError: Error, AbortError, Equatable {

    /// No usable bearer token on a protected request.
    case missingToken

    /// A bearer token was present but the validation strategy rejected it.
    case invalidToken

    public var status: HTTPResponseStatus { .unauthorized }
    public var reason: String { "Unauthorized" }
}
