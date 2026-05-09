import Foundation

/// Authentication mode shared between the OpenAPI client and the Vapor
/// server. Both sides must be started with the **same** mode — the client
/// conditionally installs the bearer-token middleware, and the server
/// conditionally installs its verification middleware, keyed on this enum.
/// Mixing modes (`.none` client talking to `.uuid` server, for example)
/// fails closed with 401 responses on protected routes.
public enum AuthMode: String, Sendable {
    /// No authentication — requests pass through without auth headers.
    /// Useful as a transitional default when an OpenAPI spec does not
    /// declare `security:` constraints, or for local development.
    case none
    /// UUID session tokens, validated by the consuming project against
    /// its own session table. The middleware enforces token *presence*;
    /// the consumer's handler validates the value.
    case uuid
    /// JWT bearer tokens. The middleware enforces token presence; the
    /// consumer's handler verifies signature, claims, and expiry.
    case jwt
}
