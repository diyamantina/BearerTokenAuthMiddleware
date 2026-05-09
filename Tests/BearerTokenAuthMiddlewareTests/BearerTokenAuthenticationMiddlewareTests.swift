import Foundation
import HTTPTypes
import OpenAPIRuntime
import Testing

@testable import BearerTokenAuthMiddleware

@Suite("BearerTokenAuthenticationMiddleware (client)")
struct BearerTokenAuthenticationMiddlewareTests {

    // MARK: - helpers

    /// Capture the request the middleware passes to `next`, plus what was
    /// written into the Authorization header (if anything).
    actor RequestCapture {
        var capturedAuthorization: String?
        func record(_ value: String?) { capturedAuthorization = value }
    }

    /// Synthetic `next` closure for `intercept`. Records the Authorization
    /// header we received, then returns a stub 200 response.
    private func makeNext(_ capture: RequestCapture)
        -> @Sendable (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    {
        return { request, body, _ in
            let auth = request.headerFields[.authorization]
            await capture.record(auth)
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
        let capture = RequestCapture()

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getThings",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == nil)
    }

    @Test("non-nil initial token writes Bearer header on outbound request")
    func tokenWritesBearerHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "abc-123")
        let capture = RequestCapture()

        // Allow the init's Task { } to run before the intercept reads the token.
        try await Task.sleep(for: .milliseconds(50))

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getThings",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == "Bearer abc-123")
    }

    @Test("updateToken changes the value used on subsequent requests")
    func updateTokenIsObservedOnNextCall() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        let capture = RequestCapture()
        try await Task.sleep(for: .milliseconds(50))

        mw.updateToken("second")
        try await Task.sleep(for: .milliseconds(50))

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getThings",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == "Bearer second")
    }

    @Test("updateToken to nil clears the header on subsequent requests")
    func updateTokenToNilClearsHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "first")
        let capture = RequestCapture()
        try await Task.sleep(for: .milliseconds(50))

        mw.updateToken(nil)
        try await Task.sleep(for: .milliseconds(50))

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getThings",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == nil)
    }

    // MARK: - skipAuthorization closure

    @Test("skipAuthorization returning true bypasses the header")
    func skipAuthorizationBypassesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "should-not-be-sent",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        let capture = RequestCapture()
        try await Task.sleep(for: .milliseconds(50))

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "publicPing",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == nil)
    }

    @Test("skipAuthorization returning false applies the header normally")
    func skipAuthorizationFalseAppliesHeader() async throws {
        let mw = BearerTokenAuthenticationMiddleware(
            initialToken: "tok",
            skipAuthorization: { opID in opID == "publicPing" }
        )
        let capture = RequestCapture()
        try await Task.sleep(for: .milliseconds(50))

        _ = try await mw.intercept(
            makeRequest(),
            body: nil,
            baseURL: baseURL,
            operationID: "getProtected",
            next: makeNext(capture)
        )

        await #expect(capture.capturedAuthorization == "Bearer tok")
    }

    // MARK: - response is forwarded unmodified

    @Test("middleware forwards the response from next unchanged")
    func responseFromNextIsForwarded() async throws {
        let mw = BearerTokenAuthenticationMiddleware(initialToken: "x")
        try await Task.sleep(for: .milliseconds(50))

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
}
