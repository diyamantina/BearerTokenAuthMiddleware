import Vapor

/// Typed errors thrown by ``BearerTokenAuthServerMiddleware``.
///
/// ## Overview
///
/// Both cases conform to `AbortError` so Vapor automatically translates them to
/// HTTP 401 with reason `"Unauthorized"`. The external response is identical for
/// both cases — per OWASP guidance, the server does not leak which sub-failure
/// tripped to a hostile caller. Tests, instrumentation, and structured logging can
/// still pattern-match on the typed case for richer signal.
///
/// | Caller sent | Thrown |
/// |---|---|
/// | nothing on `Authorization` | ``missingToken`` |
/// | `Authorization: Bearer ` (empty value) | ``missingToken`` |
/// | `Authorization: Basic ...` / Digest / etc. | ``missingToken`` |
/// | `Authorization: Bearer <bad-shape>` | ``invalidToken`` |
/// | `Authorization: Bearer <good-shape>` | (no error) |
///
/// ## Topics
///
/// ### Cases
/// - ``missingToken``
/// - ``invalidToken``
///
/// ### `AbortError` conformance
/// - ``status``
/// - ``reason``
public enum BearerTokenAuthServerError: Error, AbortError, Equatable {

    /// No usable bearer token on a protected request.
    ///
    /// Covers absent `Authorization` header, `Authorization: Bearer ` with empty
    /// value, and non-Bearer schemes (`Basic ...`, `Digest ...`, garbage).
    case missingToken

    /// A bearer token was present but the validation strategy rejected it.
    ///
    /// The bundled ``BearerTokenAuthServerMiddleware/ValidationStrategy/jwtShape``
    /// and ``BearerTokenAuthServerMiddleware/ValidationStrategy/uuidShape`` produce
    /// this on shape mismatch; ``BearerTokenAuthServerMiddleware/ValidationStrategy/custom(_:)``
    /// validators may produce this case or any other `Error` of their choosing.
    case invalidToken

    public var status: HTTPResponseStatus { .unauthorized }
    public var reason: String { "Unauthorized" }
}
