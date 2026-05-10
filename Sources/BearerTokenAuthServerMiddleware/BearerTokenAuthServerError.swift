import Vapor

/// Typed errors thrown by ``BearerTokenAuthServerMiddleware``.
///
/// ## Overview
///
/// Two cases:
///
/// - ``missingToken`` — the request had no usable bearer token on a
///   protected route. Covers absent `Authorization` header,
///   `Authorization: Bearer ` with empty value, and non-Bearer schemes
///   (`Basic ...`, `Digest ...`, garbage).
/// - ``invalidToken`` — a token was present but the configured
///   ``BearerTokenAuthServerMiddleware/ValidationStrategy`` rejected it
///   (wrong shape, signature mismatch from a `.custom` validator, etc.).
///
/// ## HTTP translation
///
/// Both cases conform to `AbortError` so Vapor automatically translates
/// them to **HTTP 401 with reason `"Unauthorized"`**. The external reason
/// is intentionally identical for both cases (OWASP guidance — do not
/// leak which sub-failure tripped to a hostile caller).
///
/// Tests, instrumentation, and structured logging can still pattern-match
/// the typed case for richer signal.
///
/// ## Mapping back to user input
///
/// | Caller sent                                | Thrown            |
/// |--------------------------------------------|-------------------|
/// | nothing on `Authorization`                 | ``missingToken``  |
/// | `Authorization: Bearer ` (empty value)     | ``missingToken``  |
/// | `Authorization: Basic ...` / Digest / etc. | ``missingToken``  |
/// | `Authorization: Bearer <bad-shape>`        | ``invalidToken``  |
/// | `Authorization: Bearer <good-shape>`       | (no error)        |
///
/// ## Topics
///
/// ### Cases
/// - ``missingToken``
/// - ``invalidToken``
///
/// ### AbortError conformance
/// - ``status``
/// - ``reason``
public enum BearerTokenAuthServerError: Error, AbortError, Equatable {

    /// No usable bearer token on a protected request.
    case missingToken

    /// A bearer token was present but the validation strategy rejected it.
    case invalidToken

    public var status: HTTPResponseStatus { .unauthorized }
    public var reason: String { "Unauthorized" }
}
