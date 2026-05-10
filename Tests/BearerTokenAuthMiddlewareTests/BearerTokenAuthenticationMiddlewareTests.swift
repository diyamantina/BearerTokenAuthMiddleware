import Foundation
import HTTPTypes
import OpenAPIRuntime
import Testing

@testable import BearerTokenAuthMiddleware

/// `BearerTokenAuthenticationMiddleware`'s `init(initialToken:)` and
/// `updateToken(_:)` write the token via a fire-and-forget `Task { ... }`,
/// so the actor write may not have landed by the time the next `intercept`
/// runs. Tests that need to observe a token write **must** poll until the
/// observable header matches expectations rather than rely on a fixed sleep.
///
/// `awaitObservedAuth` repeatedly drives a single `intercept` and returns
/// once the captured Authorization header matches `expected`, or fails the
/// surrounding test if the token never converges within the deadline.
private func awaitObservedAuth(
    on mw: BearerTokenAuthenticationMiddleware,
    operationID: String,
    expected: String?,
    timeoutMs: Int = 1000,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws {
    let baseURL = URL(string: "https://api.example.com")!
    let request = HTTPRequest(
        method: .get,
        scheme: "https",
        authority: "api.example.com",
        path: "/probe"
    )
    let intervalMs = 10
    let attempts = max(1, timeoutMs / intervalMs)
    for _ in 0..<attempts {
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
        if observed == expected { return }
        try await Task.sleep(for: .milliseconds(intervalMs))
    }
    Issue.record(
        "Authorization header never converged to \(String(describing: expected)) within \(timeoutMs)ms",
        sourceLocation: sourceLocation
    )
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
        try await awaitObservedAuth(on: mw, operationID: "op", expected: nil)
    }

    @Test("non-nil initial token writes Bearer header on outbound request")
    func tokenWritesBearerHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "abc-123")
        try await awaitObservedAuth(on: mw, operationID: "op", expected: "Bearer abc-123")
    }

    @Test("updateToken changes the value used on subsequent requests")
    func updateTokenIsObservedOnNextCall() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        try await awaitObservedAuth(on: mw, operationID: "op", expected: "Bearer first")
        mw.updateToken("second")
        try await awaitObservedAuth(on: mw, operationID: "op", expected: "Bearer second")
    }

    @Test("updateToken to nil clears the header on subsequent requests")
    func updateTokenToNilClearsHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        try await awaitObservedAuth(on: mw, operationID: "op", expected: "Bearer first")
        mw.updateToken(nil)
        try await awaitObservedAuth(on: mw, operationID: "op", expected: nil)
    }

    // MARK: - skipAuthorization closure

    @Test("skipAuthorization returning true bypasses the header")
    func skipAuthorizationBypassesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "should-not-be-sent",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        try await awaitObservedAuth(on: mw, operationID: "publicPing", expected: nil)
    }

    @Test("skipAuthorization returning false applies the header normally")
    func skipAuthorizationFalseAppliesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "tok",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        try await awaitObservedAuth(on: mw, operationID: "getProtected", expected: "Bearer tok")
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

        // Drive once to force the actor write to land. We don't assert the
        // value, just consume any race window so the next intercept is clean.
        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "warmup",
            next: { _, _, _ in (HTTPResponse(status: .ok), nil) }
        )

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
