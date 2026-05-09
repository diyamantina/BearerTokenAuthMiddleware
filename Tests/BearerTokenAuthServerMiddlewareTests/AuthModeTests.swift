import Foundation
import Testing

@testable import BearerTokenAuthServerMiddleware

@Suite("AuthMode")
struct AuthModeTests {

    @Test("rawValue mappings")
    func rawValues() {
        #expect(AuthMode.none.rawValue == "none")
        #expect(AuthMode.uuid.rawValue == "uuid")
        #expect(AuthMode.jwt.rawValue == "jwt")
    }

    @Test("init from rawValue")
    func initFromRaw() {
        // Fully-qualified case names disambiguate from `Optional.none`.
        #expect(AuthMode(rawValue: "none") == AuthMode.none)
        #expect(AuthMode(rawValue: "uuid") == AuthMode.uuid)
        #expect(AuthMode(rawValue: "jwt") == AuthMode.jwt)
        #expect(AuthMode(rawValue: "bogus") == nil)
    }

    @Test("Sendable conformance compiles in concurrent context")
    func sendable() async {
        let mode: AuthMode = .uuid
        async let copy = mode
        let received = await copy
        #expect(received == .uuid)
    }
}

@Suite("BearerTokenContext")
struct BearerTokenContextTests {

    private func readToken() async -> String? { BearerTokenContext.token }

    @Test("default value is nil")
    func defaultIsNil() {
        #expect(BearerTokenContext.token == nil)
    }

    @Test("withValue scopes a token to the closure")
    func withValueScopesToken() {
        BearerTokenContext.$token.withValue("scoped") {
            #expect(BearerTokenContext.token == "scoped")
        }
        #expect(BearerTokenContext.token == nil)
    }

    @Test("withValue propagates across an `await` boundary inside the closure")
    func withValuePropagatesAcrossAwait() async {
        let observed = await BearerTokenContext.$token.withValue("propagated") {
            await readToken()
        }
        #expect(observed == "propagated")
    }

    @Test("withValue does not leak to siblings outside the closure")
    func withValueDoesNotLeak() async {
        await BearerTokenContext.$token.withValue("inside") { }
        #expect(BearerTokenContext.token == nil)
    }
}
