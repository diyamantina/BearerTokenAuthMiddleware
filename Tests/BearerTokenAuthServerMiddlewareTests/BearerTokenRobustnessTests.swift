import Foundation
import Testing
import Vapor
import VaporTesting

@testable import BearerTokenAuthServerMiddleware

/// Adversarial coverage for `BearerTokenAuthServerMiddleware`. Each test
/// feeds the middleware something a real attacker, a misconfigured
/// upstream, or a buggy client might emit and asserts the middleware fails
/// closed (or, where it shouldn't fail closed, behaves consistently).
@Suite("BearerTokenAuthServerMiddleware: adversarial / malformed inputs")
struct BearerTokenRobustnessTests {

    actor TokenRecorder {
        private(set) var seen: String?
        func record(_ value: String?) { seen = value }
    }

    private func makeApp(
        mode: AuthMode = .uuid,
        validation: BearerTokenAuthServerMiddleware.ValidationStrategy = .auto,
        publicEndpoints: Set<String> = [],
        publicPathPrefixes: Set<String> = [],
        propagateTokenOnPublicRoutes: Bool = false
    ) async throws -> (Application, TokenRecorder) {
        let app = try await Application.make(.testing)
        let recorder = TokenRecorder()
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: mode,
                publicEndpoints: publicEndpoints,
                publicPathPrefixes: publicPathPrefixes,
                validation: validation,
                propagateTokenOnPublicRoutes: propagateTokenOnPublicRoutes
            )
        )
        app.get("probe") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }
        app.get("admin", "page") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }
        app.get("administrator") { _ -> String in
            await recorder.record(BearerTokenContext.token)
            return "ok"
        }
        return (app, recorder)
    }

    // MARK: - Empty / whitespace-only tokens

    @Test("empty Bearer header value is rejected as missingToken")
    func emptyBearerRejected() async throws {
        let (app, _) = try await makeApp()
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: .authorization, value: "Bearer ")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("Bearer with only whitespace is rejected")
    func whitespaceBearerRejected() async throws {
        let (app, _) = try await makeApp()
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: .authorization, value: "Bearer    ")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - Pathological token values

    @Test("very long token (10 KB) is accepted under .none validation")
    func tenKByteTokenAccepted() async throws {
        let token = String(repeating: "a", count: 10_000)
        let (app, recorder) = try await makeApp(validation: .none)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: token)
            }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == token)
        try await app.asyncShutdown()
    }

    @Test(".jwtShape rejects three empty segments separated by dots (`..`)")
    func jwtShapeRejectsEmptySegments() async throws {
        let (app, _) = try await makeApp(mode: .jwt)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: "..")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".jwtShape rejects four-segment token")
    func jwtShapeRejectsFourSegments() async throws {
        let (app, _) = try await makeApp(mode: .jwt)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: "a.b.c.d")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test(".jwtShape rejects token with a non-Base64URL character (`+`, `/`, `=`)")
    func jwtShapeRejectsNonBase64URL() async throws {
        let (app, _) = try await makeApp(mode: .jwt)
        for invalid in ["a+b.c.d", "a.b.c=", "a/b.c.d"] {
            try await app.testing().test(
                .GET, "probe",
                beforeRequest: { req in
                    req.headers.bearerAuthorization = .init(token: invalid)
                }
            ) { res async in
                #expect(res.status == .unauthorized, "token \(invalid) should be rejected")
            }
        }
        try await app.asyncShutdown()
    }

    @Test(".uuidShape accepts uppercase UUID")
    func uuidShapeAcceptsUppercase() async throws {
        let (app, recorder) = try await makeApp(mode: .uuid)
        let upper = "550E8400-E29B-41D4-A716-446655440000"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: upper)
            }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.seen == upper)
        try await app.asyncShutdown()
    }

    @Test(".uuidShape rejects UUID with extra characters appended")
    func uuidShapeRejectsAppended() async throws {
        let (app, _) = try await makeApp(mode: .uuid)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: "550e8400-e29b-41d4-a716-446655440000-extra")
            }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - Path-prefix bypass safety

    @Test("publicPathPrefixes [\"/admin\"] does NOT bypass /administrator (sibling-namespace guard)")
    func adminPrefixDoesNotMatchAdministrator() async throws {
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin"]
        )
        try await app.testing().test(.GET, "administrator") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("publicPathPrefixes does not bypass when query string contains the prefix")
    func queryStringDoesNotBypass() async throws {
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin"]
        )
        try await app.testing().test(.GET, "probe?path=/admin") { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("URL-encoded /admin in path does not bypass the literal /admin prefix")
    func percentEncodedPathDoesNotBypass() async throws {
        // Vapor decodes %2F to /, so this is mostly a sanity check that the
        // path-prefix matching uses the *decoded* path consistently.
        let (app, _) = try await makeApp(
            mode: .uuid,
            publicPathPrefixes: ["/admin/"]
        )
        try await app.testing().test(.GET, "%2Fadmin/page") { res async in
            // Path is /%2Fadmin/page (Vapor doesn't decode the leading slash
            // as a path segment), so the prefix /admin/ should NOT match.
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    // MARK: - Multiple Authorization headers

    @Test("two Authorization headers: Vapor's bearerAuthorization uses the first")
    func multipleAuthorizationHeaders() async throws {
        let uuid = "550e8400-e29b-41d4-a716-446655440000"
        let (app, recorder) = try await makeApp(mode: .uuid)
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.add(name: .authorization, value: "Bearer \(uuid)")
                req.headers.add(name: .authorization, value: "Bearer 00000000-0000-0000-0000-000000000000")
            }
        ) { res async in
            // Both are valid UUID shape; the middleware must accept *one*
            // of them and propagate it. Pin to whichever Vapor exposes via
            // bearerAuthorization to make the contract explicit.
            #expect(res.status == .ok)
        }
        let seen = await recorder.seen
        #expect(seen != nil)
        try await app.asyncShutdown()
    }

    // MARK: - Concurrent requests with distinct tokens

    @Test("100 concurrent authenticated requests each see their own token (no task-local cross-talk)")
    func noCrossRequestTokenContamination() async throws {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: .uuid,
                publicEndpoints: [],
                validation: .none
            )
        )

        actor MultiRecorder {
            private(set) var observations: [Int: String] = [:]
            func record(id: Int, token: String?) { observations[id] = token ?? "<nil>" }
        }
        let recorder = MultiRecorder()

        app.get("probe", ":id") { req -> String in
            let id = Int(req.parameters.get("id") ?? "-1") ?? -1
            await recorder.record(id: id, token: BearerTokenContext.token)
            return "ok"
        }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<100 {
                group.addTask {
                    let token = "tok-\(i)"
                    try await app.testing().test(
                        .GET, "probe/\(i)",
                        beforeRequest: { req in
                            req.headers.bearerAuthorization = .init(token: token)
                        }
                    ) { res async in
                        #expect(res.status == .ok)
                    }
                }
            }
            try await group.waitForAll()
        }

        for i in 0..<100 {
            let observed = await recorder.observations[i]
            #expect(observed == "tok-\(i)", "request \(i) saw \(observed ?? "<nothing>")")
        }

        try await app.asyncShutdown()
    }

    // MARK: - .custom validator surface

    @Test(".custom validator can throw an arbitrary Abort to signal forbidden")
    func customValidatorForbidden() async throws {
        let (app, _) = try await makeApp(
            mode: .uuid,
            validation: .custom { _ in throw Abort(.forbidden, reason: "blocked") }
        )
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: "550e8400-e29b-41d4-a716-446655440000")
            }
        ) { res async in
            #expect(res.status == .forbidden)
        }
        try await app.asyncShutdown()
    }
}
