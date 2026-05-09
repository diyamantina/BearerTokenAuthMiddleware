import Foundation
import Testing
import Vapor
import VaporTesting

@testable import BearerTokenAuthServerMiddleware

@Suite("BearerTokenAuthServerMiddleware (server)")
struct BearerTokenAuthServerMiddlewareTests {

    /// Captures what `BearerTokenContext.token` was at handler-time, so tests
    /// can verify the middleware propagated the token correctly.
    actor TokenRecorder {
        private(set) var seen: String?
        func record(_ value: String?) { seen = value }
    }

    /// Spin up an in-process Vapor app with the middleware installed and a
    /// single route at `GET /probe` that records `BearerTokenContext.token`.
    @discardableResult
    private func makeApp(
        mode: AuthMode = .none,
        publicEndpoints: Set<String> = [],
        publicPathPrefixes: Set<String> = [],
        maxTokenLength: Int = 4096
    ) async throws -> (Application, TokenRecorder) {
        let app = try await Application.make(.testing)
        let recorder = TokenRecorder()

        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: mode,
                publicEndpoints: publicEndpoints,
                publicPathPrefixes: publicPathPrefixes,
                maxTokenLength: maxTokenLength
            )
        )

        app.get("probe") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }
        app.get("public") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }
        app.get("admin", "page") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }

        return (app, recorder)
    }

    // MARK: - .none mode

    @Test(".none mode passes through without a token")
    func noneNoToken() async throws {
        let (app, recorder) = try await makeApp(mode: .none)
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == nil)
        try await app.asyncShutdown()
    }

    @Test(".none mode passes through but propagates token if present")
    func nonePropagatesPresentToken() async throws {
        let (app, recorder) = try await makeApp(mode: .none)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "tok-1") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "tok-1")
        try await app.asyncShutdown()
    }

    // MARK: - .uuid mode (representative of any non-.none mode)

    @Test(".uuid mode rejects a request with no Authorization header")
    func uuidRejectsMissingToken() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode accepts a request with a valid token, propagates to handler")
    func uuidAcceptsValidToken() async throws {
        let (app, recorder) = try await makeApp(mode: .uuid)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "good") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "good")
        try await app.asyncShutdown()
    }

    @Test(".uuid mode rejects an empty bearer token")
    func uuidRejectsEmptyToken() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.replaceOrAdd(name: .authorization, value: "Bearer ") }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode rejects a token longer than maxTokenLength")
    func uuidRejectsOversizedToken() async throws {
        let (app, _) = try await makeApp(mode: .uuid, maxTokenLength: 16)
        let oversized = String(repeating: "x", count: 32)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: oversized) }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode allows token exactly at maxTokenLength")
    func uuidAllowsBoundaryToken() async throws {
        let (app, recorder) = try await makeApp(mode: .uuid, maxTokenLength: 16)
        let exact = String(repeating: "y", count: 16)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: exact) }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == exact)
        try await app.asyncShutdown()
    }

    // MARK: - public endpoint exact match

    @Test(".uuid mode lets exact-match public endpoints through without a token")
    func uuidPublicEndpointBypass() async throws {
        let (app, recorder) = try await makeApp(
            mode: .uuid,
            publicEndpoints: ["/public"]
        )
        try await app.testing().test(.GET, "public") { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == nil)
        try await app.asyncShutdown()
    }

    @Test(".uuid mode public endpoint still propagates token when one is sent")
    func uuidPublicEndpointPropagatesPresentToken() async throws {
        let (app, recorder) = try await makeApp(
            mode: .uuid,
            publicEndpoints: ["/public"]
        )
        try await app.testing().test(
            .GET,
            "public",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "anon") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "anon")
        try await app.asyncShutdown()
    }

    // MARK: - public path prefix

    @Test(".uuid mode lets paths under publicPathPrefixes through without a token")
    func uuidPublicPathPrefixBypass() async throws {
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin/"]
        )
        try await app.testing().test(.GET, "admin/page") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode does NOT bypass paths just because a prefix substring matches mid-path")
    func uuidPathPrefixIsLeftAnchored() async throws {
        // `publicPathPrefixes: ["/admin/"]` should NOT bypass `/probe`.
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin/"]
        )
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - .jwt mode behaves identically to .uuid for enforcement

    @Test(".jwt mode rejects missing token, accepts present token")
    func jwtRejectsAndAccepts() async throws {
        let (app, recorder) = try await makeApp(mode: .jwt)
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "jwt-here") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "jwt-here")
        try await app.asyncShutdown()
    }

    // MARK: - default init values

    @Test("default init mode is .none — protected routes pass through")
    func defaultInitIsNone() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(BearerTokenAuthServerMiddleware())
        app.get("anything") { _ in "ok" }
        try await app.testing().test(.GET, "anything") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }
}
