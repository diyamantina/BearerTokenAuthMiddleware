import Foundation
import Testing
import Vapor
import VaporTesting

@testable import BearerTokenAuthServerMiddleware

@Suite("BearerTokenAuthServerMiddleware (server)")
struct BearerTokenAuthServerMiddlewareTests {

    actor TokenRecorder {
        private(set) var seen: String?
        func record(_ value: String?) { seen = value }
    }

    /// Spin up a Vapor app with the middleware installed using the
    /// supplied options (or pure defaults). Routes:
    /// - GET /probe         → records BearerTokenContext.token
    /// - GET /public        → records BearerTokenContext.token
    /// - GET /admin/page    → records BearerTokenContext.token
    /// - GET /health        → covered by default public endpoints
    @discardableResult
    private func makeApp(
        mode: AuthMode = .none,
        publicEndpoints: Set<String>? = nil,
        publicPathPrefixes: Set<String> = [],
        validation: BearerTokenAuthServerMiddleware.ValidationStrategy = .auto
    ) async throws -> (Application, TokenRecorder) {
        let app = try await Application.make(.testing)
        let recorder = TokenRecorder()

        let mw: BearerTokenAuthServerMiddleware
        if let publicEndpoints {
            mw = BearerTokenAuthServerMiddleware(
                mode: mode,
                publicEndpoints: publicEndpoints,
                publicPathPrefixes: publicPathPrefixes,
                validation: validation
            )
        } else {
            // Use the defaults
            mw = BearerTokenAuthServerMiddleware(
                mode: mode,
                publicPathPrefixes: publicPathPrefixes,
                validation: validation
            )
        }
        app.middleware.use(mw)

        for path in [["probe"], ["public"], ["admin", "page"], ["health"]] {
            app.get(path.map(PathComponent.init(stringLiteral:))) { _ -> String in
                await recorder.record(BearerTokenContext.token)
                return "ok"
            }
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

    @Test(".none mode propagates the token if one is present")
    func nonePropagatesPresentToken() async throws {
        let (app, recorder) = try await makeApp(mode: .none)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "tok-1") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "tok-1")
        try await app.asyncShutdown()
    }

    // MARK: - .uuid mode rejects missing token (default validation = .uuidShape now)

    @Test(".uuid mode rejects request with no Authorization header")
    func uuidRejectsMissingToken() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode with default validation accepts a canonical UUID, propagates")
    func uuidAcceptsCanonicalUUID() async throws {
        let (app, recorder) = try await makeApp(mode: .uuid)
        let uuid = "550e8400-e29b-41d4-a716-446655440000"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: uuid) }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == uuid)
        try await app.asyncShutdown()
    }

    @Test(".uuid mode with default validation REJECTS a non-UUID token")
    func uuidRejectsNonUUID() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "not-a-uuid") }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode with explicit validation: .none accepts ANY non-empty token")
    func uuidWithExplicitNoneValidationAcceptsAnything() async throws {
        let (app, _) = try await makeApp(mode: .uuid, validation: .none)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "any-string") }
        ) { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    // MARK: - .jwt mode (default validation = .jwtShape)

    @Test(".jwt mode rejects missing, accepts valid-shape JWT, rejects malformed")
    func jwtModeDefaults() async throws {
        let (app, recorder) = try await makeApp(mode: .jwt)
        // missing
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        // good shape
        let goodJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc-_DEF"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: goodJWT) }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == goodJWT)
        // malformed
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "not-jwt") }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - default public endpoints (health/ready/metrics)

    @Test(".uuid mode lets default public endpoints (/health) through without a token")
    func defaultHealthEndpointBypass() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(.GET, "health") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("constructor literal default exposes /health, /healthz, /ready, /readyz, /metrics")
    func defaultPublicEndpointsContents() {
        let defaults = BearerTokenAuthServerMiddleware.defaultPublicEndpoints
        #expect(defaults.contains("/health"))
        #expect(defaults.contains("/healthz"))
        #expect(defaults.contains("/ready"))
        #expect(defaults.contains("/readyz"))
        #expect(defaults.contains("/metrics"))
    }

    @Test("explicit empty publicEndpoints overrides the default — health is now protected")
    func emptyPublicEndpointsOverridesDefault() async throws {
        let (app, _) = try await makeApp(mode: .uuid, publicEndpoints: [])
        try await app.testing().test(.GET, "health") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - public path prefix (still works alongside default endpoints)

    @Test(".uuid mode lets paths under publicPathPrefixes through")
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
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin/"]
        )
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
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

// MARK: - Path-prefix boundary safety

@Suite("Path-prefix boundary matching")
struct PathPrefixBoundaryTests {
    private func makeApp(prefixes: Set<String>) async throws -> Application {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: .uuid,
                publicEndpoints: [],
                publicPathPrefixes: prefixes,
                validation: .none
            )
        )
        app.get("admin") { _ in "ok" }
        app.get("admin", "page") { _ in "ok" }
        app.get("administrator") { _ in "ok" }
        app.get("admins", "list") { _ in "ok" }
        return app
    }

    @Test("prefix `/admin` matches `/admin` exactly")
    func exactMatch() async throws {
        let app = try await makeApp(prefixes: ["/admin"])
        try await app.testing().test(.GET, "admin") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("prefix `/admin` matches `/admin/page` (component boundary)")
    func componentBoundaryMatch() async throws {
        let app = try await makeApp(prefixes: ["/admin"])
        try await app.testing().test(.GET, "admin/page") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("prefix `/admin` does NOT match `/administrator` (security regression guard)")
    func doesNotMatchSiblingNamespace() async throws {
        let app = try await makeApp(prefixes: ["/admin"])
        try await app.testing().test(.GET, "administrator") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("prefix `/admin` does NOT match `/admins/list`")
    func doesNotMatchPluralNamespace() async throws {
        let app = try await makeApp(prefixes: ["/admin"])
        try await app.testing().test(.GET, "admins/list") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("prefix `/admin/` (trailing slash) is equivalent to `/admin`")
    func trailingSlashEquivalent() async throws {
        let app = try await makeApp(prefixes: ["/admin/"])
        try await app.testing().test(.GET, "admin") { res async in
            #expect(res.status == .ok)
        }
        try await app.testing().test(.GET, "admin/page") { res async in
            #expect(res.status == .ok)
        }
        try await app.testing().test(.GET, "administrator") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }
}

// MARK: - Non-Bearer Authorization schemes

@Suite("Non-Bearer Authorization schemes")
struct NonBearerAuthorizationTests {
    private func makeApp() async throws -> Application {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: .uuid,
                publicEndpoints: [],
                validation: .none
            )
        )
        app.get("probe") { _ in "ok" }
        return app
    }

    @Test("`Authorization: Basic abc` is treated as missing")
    func basicAuthRejected() async throws {
        let app = try await makeApp()
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: .authorization, value: "Basic dXNlcjpwYXNz")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("`Authorization: Digest ...` is treated as missing")
    func digestAuthRejected() async throws {
        let app = try await makeApp()
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: .authorization, value: "Digest username=\"x\"")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("garbage Authorization header is treated as missing")
    func garbageAuthRejected() async throws {
        let app = try await makeApp()
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: .authorization, value: "totally-not-a-scheme")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }
}

// MARK: - HTTP methods

@Suite("HTTP methods")
struct HTTPMethodTests {

    actor TokenRecorder {
        private(set) var seen: String?
        func record(_ value: String?) { seen = value }
    }

    private func makeApp() async throws -> (Application, TokenRecorder) {
        let app = try await Application.make(.testing)
        let recorder = TokenRecorder()
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: .uuid,
                publicEndpoints: [],
                validation: .none
            )
        )
        for method in [HTTPMethod.GET, .POST, .PUT, .PATCH, .DELETE] {
            app.on(method, "thing") { _ -> String in
                await recorder.record(BearerTokenContext.token)
                return "ok"
            }
        }
        return (app, recorder)
    }

    @Test("non-GET methods enforce too", arguments: [
        ("POST",   HTTPMethod.POST),
        ("PUT",    HTTPMethod.PUT),
        ("PATCH",  HTTPMethod.PATCH),
        ("DELETE", HTTPMethod.DELETE),
    ])
    func nonGETMethodsEnforce(_ name: String, _ method: HTTPMethod) async throws {
        let (app, recorder) = try await makeApp()
        try await app.testing().test(method, "thing") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.testing().test(
            method, "thing",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "t-\(name)") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == "t-\(name)")
        try await app.asyncShutdown()
    }
}

@Suite("Path-prefix init normalization")
struct PathPrefixNormalizationTests {
    @Test("empty prefix is filtered out (does not match every path)")
    func emptyPrefixFiltered() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: .uuid,
                publicEndpoints: [],
                publicPathPrefixes: ["", "/", "/public"],
                validation: .none
            )
        )
        app.get("anything") { _ in "ok" }
        try await app.testing().test(.GET, "anything") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }
}

// MARK: - Auto-picked validation strategy

@Suite("Auto-picked ValidationStrategy")
struct AutoValidationTests {
    @Test(".none mode → no validation (any non-empty token accepted on protected route)")
    func noneAutoValidation() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(mode: .none)
        )
        app.get("probe") { _ in "ok" }
        // .none mode never enforces, so even probe is open
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test(".uuid mode → validation auto-picks .uuidShape (rejects non-UUID)")
    func uuidAutoValidation() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(mode: .uuid, publicEndpoints: [])
        )
        app.get("probe") { _ in "ok" }
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "not-uuid") }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".jwt mode → validation auto-picks .jwtShape (rejects non-JWT)")
    func jwtAutoValidation() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(mode: .jwt, publicEndpoints: [])
        )
        app.get("probe") { _ in "ok" }
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "not-jwt") }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }
}
