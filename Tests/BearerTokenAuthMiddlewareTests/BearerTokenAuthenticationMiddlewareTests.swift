import Foundation
import HTTPTypes
import OpenAPIRuntime
import Testing

@testable import BearerTokenAuthMiddleware

/// Drives a single `intercept` call and returns the observed `Authorization` header.
///
/// `BearerTokenAuthenticationMiddleware`'s token storage is a synchronous, lock-protected
/// write/read (not an actor written to via a detached `Task`), so a token set by `init` or
/// `updateToken(_:)` is visible to the very next `intercept` call with no race window —
/// one direct call is enough to observe it, no polling needed.
private func observedAuth(
    on mw: BearerTokenAuthenticationMiddleware,
    operationID: String
) async throws -> String? {
    let baseURL = URL(string: "https://api.example.com")!
    let request = HTTPRequest(
        method: .get,
        scheme: "https",
        authority: "api.example.com",
        path: "/probe"
    )
    var observed: String?
    _ = try await mw.intercept(
        request,
        body: nil,
        baseURL: baseURL,
        operationID: operationID,
        next: { req, _, _ in
            observed = req.headerFields[.authorization]
            return (HTTPResponse(status: .ok), nil)
        }
    )
    return observed
}

@Suite("BearerTokenAuthenticationMiddleware (client)")
struct BearerTokenAuthenticationMiddlewareTests {

    actor RequestCapture {
        private(set) var capturedAuthorization: String?
        private(set) var capturedBody: Data?
        func record(_ value: String?, body: HTTPBody?) async {
            capturedAuthorization = value
            if let body { capturedBody = try? await Data(collecting: body, upTo: .max) }
        }
    }

    private func makeNext(_ capture: RequestCapture)
        -> @Sendable (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    {
        return { request, body, _ in
            let auth = request.headerFields[.authorization]
            await capture.record(auth, body: body)
            return (HTTPResponse(status: .ok), nil)
        }
    }

    private func makeRequest() -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "api.example.com", path: "/things")
    }

    private let baseURL = URL(string: "https://api.example.com")!

    // MARK: - basic token application

    @Test("nil initial token leaves Authorization header unset")
    func nilInitialTokenSetsNoHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: nil)
        #expect(try await observedAuth(on: mw, operationID: "op") == nil)
    }

    @Test("non-nil initial token writes Bearer header on outbound request")
    func tokenWritesBearerHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "abc-123")
        #expect(try await observedAuth(on: mw, operationID: "op") == "Bearer abc-123")
    }

    @Test("updateToken changes the value used on the very next request")
    func updateTokenIsObservedOnNextCall() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        #expect(try await observedAuth(on: mw, operationID: "op") == "Bearer first")
        mw.updateToken("second")
        #expect(try await observedAuth(on: mw, operationID: "op") == "Bearer second")
    }

    @Test("updateToken to nil clears the header on the very next request")
    func updateTokenToNilClearsHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        #expect(try await observedAuth(on: mw, operationID: "op") == "Bearer first")
        mw.updateToken(nil)
        #expect(try await observedAuth(on: mw, operationID: "op") == nil)
    }

    // MARK: - skipAuthorization closure

    @Test("skipAuthorization returning true bypasses the header")
    func skipAuthorizationBypassesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "should-not-be-sent",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        #expect(try await observedAuth(on: mw, operationID: "publicPing") == nil)
    }

    @Test("skipAuthorization returning false applies the header normally")
    func skipAuthorizationFalseAppliesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "tok",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        #expect(try await observedAuth(on: mw, operationID: "getProtected") == "Bearer tok")
    }

    // MARK: - response is forwarded unmodified

    @Test("middleware forwards the response from next unchanged")
    func responseFromNextIsForwarded() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "x")
        let (response, _) = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getThings",
            next: { _, _, _ in
                (HTTPResponse(status: .notFound), nil)
            }
        )
        #expect(response.status == .notFound)
    }

    // MARK: - body forwarding

    @Test("middleware forwards request body unchanged")
    func bodyIsForwardedUnchanged() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "tok")
        let capture = RequestCapture()
        let payload = #"{"hello":"world"}"#.data(using: .utf8)!

        let body = HTTPBody(payload)
        _ = try await mw.intercept(
            HTTPRequest(method: .post, scheme: "https", authority: "api.example.com", path: "/echo"),
            body: body,
            baseURL: baseURL,
            operationID: "echo",
            next: makeNext(capture)
        )

        await #expect(capture.capturedBody == payload)
    }
}
