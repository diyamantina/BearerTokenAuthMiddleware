import Foundation

/// Authentication mode shared between the OpenAPI client and the Vapor server.
///
/// ## Overview
///
/// Both sides must be started with the **same** mode — the client side conditionally
/// installs `BearerTokenAuthenticationMiddleware` (from the sibling
/// `BearerTokenAuthMiddleware` product) and the server side conditionally installs
/// ``BearerTokenAuthServerMiddleware``, keyed on this enum. Mixing modes
/// (`.none` client talking to `.uuid` server, for example) fails closed: the server
/// returns 401 on protected routes because the client never sent a token.
///
/// The default ``none`` is appropriate for transitional projects that have not yet
/// defined `security:` constraints in their OpenAPI spec. Use ``uuid`` when your
/// server validates session tokens against a database table; use ``jwt`` when your
/// tokens are signed JWTs verified against a signing key.
///
/// ## Topics
///
/// ### Modes
/// - ``none``
/// - ``uuid``
/// - ``jwt``
public enum AuthMode: String, Sendable {

    /// No authentication — requests pass through without auth headers.
    ///
    /// Useful as a transitional default when an OpenAPI spec does not declare
    /// `security:` constraints, or for local development.
    case none

    /// UUID session tokens, validated by the consuming project against its own
    /// session store.
    ///
    /// The middleware enforces token *presence*; the consumer's handler validates
    /// the value (DB lookup + expiry).
    case uuid

    /// JWT bearer tokens, validated by the consuming project against its signing key.
    ///
    /// The middleware enforces token presence; the consumer's handler verifies
    /// signature, claims (`exp`, `iat`, `nbf`), and audience.
    case jwt
}
