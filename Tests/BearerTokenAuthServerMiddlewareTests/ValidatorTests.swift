import Foundation
import Testing
import Vapor
import VaporTesting

@testable import BearerTokenAuthServerMiddleware

@Suite("ValidationStrategy.custom")
struct CustomValidationTests {

    actor ValidatorRecorder {
        private(set) var calls: [String] = []
        func record(_ token: String) { calls.append(token) }
    }

    private func makeApp(
        mode: AuthMode = .uuid,
        publicEndpoints: Set<String> = [],
        validator: @escaping BearerTokenAuthServerMiddleware.Validator = { _ in }
    ) async throws -> (Application, ValidatorRecorder) {
        let app = try await Application.make(.testing)
        let recorder = ValidatorRecorder()
        let wrapped: BearerTokenAuthServerMiddleware.Validator = { token in
            await recorder.record(token)
            try await validator(token)
        }
        app.middleware.use(
            BearerTokenAuthServerMiddleware(
                mode: mode,
                publicEndpoints: publicEndpoints,
                validation: .custom(wrapped)
            )
        )
        app.get("probe") { _ in "ok" }
        app.get("public") { _ in "ok" }
        return (app, recorder)
    }

    @Test("validator IS called with the token on a protected route")
    func validatorCalledOnProtected() async throws {
        let (app, recorder) = try await makeApp()
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "tok-1") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.calls == ["tok-1"])
        try await app.asyncShutdown()
    }

    @Test("validator throwing a custom Abort propagates through to HTTP response")
    func validatorThrowingPropagates() async throws {
        let (app, _) = try await makeApp { _ in
            throw Abort(.forbidden, reason: "validator says no")
        }
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "anything") }
        ) { res async in
            #expect(res.status == .forbidden)
        }
        try await app.asyncShutdown()
    }

    @Test("validator is NOT called when token is missing")
    func validatorNotCalledOnMissingToken() async throws {
        let (app, recorder) = try await makeApp()
        try await app.testing().test(.GET, "probe") { res async in
            #expect(res.status == .unauthorized)
        }
        await #expect(recorder.calls.isEmpty)
        try await app.asyncShutdown()
    }

    @Test("validator is NOT called in .none mode")
    func validatorNotCalledInNoneMode() async throws {
        let (app, recorder) = try await makeApp(mode: .none)
        try await app.testing().test(
            .GET,
            "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "tok") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.calls.isEmpty)
        try await app.asyncShutdown()
    }

    @Test("validator is NOT called for public endpoints")
    func validatorNotCalledForPublicEndpoint() async throws {
        let (app, recorder) = try await makeApp(publicEndpoints: ["/public"])
        try await app.testing().test(
            .GET,
            "public",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: "tok") }
        ) { res async in
            #expect(res.status == .ok)
        }
        await #expect(recorder.calls.isEmpty)
        try await app.asyncShutdown()
    }
}

@Suite("ValidationStrategy.jwtShape")
struct JWTShapeValidationTests {

    private func makeApp() async throws -> Application {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(mode: .jwt, validation: .jwtShape)
        )
        app.get("probe") { _ in "ok" }
        return app
    }

    @Test("accepts a valid 3-segment Base64URL JWT shape")
    func acceptsValidShape() async throws {
        let app = try await makeApp()
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc-_DEF"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
        ) { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("rejects token with wrong segment count")
    func rejectsWrongSegmentCount() async throws {
        let app = try await makeApp()
        for token in ["only-one", "two.parts", "four.parts.here.now"] {
            try await app.testing().test(
                .GET, "probe",
                beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
        try await app.asyncShutdown()
    }

    @Test("rejects token with non-Base64URL characters (`+` `/` `=`)")
    func rejectsNonBase64URLChars() async throws {
        let app = try await makeApp()
        let bad = "eyJhbGc=.payload.+sig/x"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: bad) }
        ) { res async in
            #expect(res.status == .unauthorized)
        }
        try await app.asyncShutdown()
    }

    @Test("rejects token with empty segment")
    func rejectsEmptySegment() async throws {
        let app = try await makeApp()
        for token in ["..signature", "header..signature", "header.payload."] {
            try await app.testing().test(
                .GET, "probe",
                beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
        try await app.asyncShutdown()
    }
}

@Suite("ValidationStrategy.uuidShape")
struct UUIDShapeValidationTests {

    private func makeApp() async throws -> Application {
        let app = try await Application.make(.testing)
        app.middleware.use(
            BearerTokenAuthServerMiddleware(mode: .uuid, validation: .uuidShape)
        )
        app.get("probe") { _ in "ok" }
        return app
    }

    @Test("accepts a canonical 8-4-4-4-12 UUID")
    func acceptsCanonicalUUID() async throws {
        let app = try await makeApp()
        let token = "550E8400-E29B-41D4-A716-446655440000"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
        ) { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("accepts lowercase UUID")
    func acceptsLowercaseUUID() async throws {
        let app = try await makeApp()
        let token = "550e8400-e29b-41d4-a716-446655440000"
        try await app.testing().test(
            .GET, "probe",
            beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
        ) { res async in
            #expect(res.status == .ok)
        }
        try await app.asyncShutdown()
    }

    @Test("rejects garbage-shaped tokens")
    func rejectsGarbage() async throws {
        let app = try await makeApp()
        for token in [
            "not-a-uuid",
            "550E8400-E29B-41D4-A716-44665544000",
            "550E8400E29B41D4A716446655440000",
            "abc"
        ] {
            try await app.testing().test(
                .GET, "probe",
                beforeRequest: { req in req.headers.bearerAuthorization = .init(token: token) }
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
        try await app.asyncShutdown()
    }
}

@Suite("BearerTokenAuthServerError typed cases")
struct TypedErrorTests {

    /// Vapor translates AbortError to HTTP responses, but inside Swift we
    /// can intercept the error before Vapor sees it by calling the
    /// middleware directly with a hand-made Request.
    private func runThroughMiddleware(
        mode: AuthMode = .uuid,
        validation: BearerTokenAuthServerMiddleware.ValidationStrategy = .none,
        maxTokenLength: Int = 4096,
        authorization: String? = nil,
        path: String = "/probe"
    ) async throws -> Result<Response, Error> {
        let app = try await Application.make(.testing)
        defer { Task { try? await app.asyncShutdown() } }
        let mw = BearerTokenAuthServerMiddleware(
            mode: mode,
            maxTokenLength: maxTokenLength,
            validation: validation
        )
        let req = Request(
            application: app,
            method: .GET,
            url: URI(path: path),
            on: app.eventLoopGroup.next()
        )
        if let authorization {
            req.headers.replaceOrAdd(name: .authorization, value: authorization)
        }
        struct OK: AsyncResponder {
            func respond(to request: Request) async throws -> Response {
                Response(status: .ok)
            }
        }
        do {
            let res = try await mw.respond(to: req, chainingTo: OK())
            return .success(res)
        } catch {
            return .failure(error)
        }
    }

    @Test(".missingToken is thrown when Authorization header is absent")
    func missingTokenError() async throws {
        let result = try await runThroughMiddleware()
        guard case .failure(let error) = result,
              let typed = error as? BearerTokenAuthServerError else {
            Issue.record("expected BearerTokenAuthServerError, got \(result)")
            return
        }
        #expect(typed == .missingToken)
        #expect(typed.status == .unauthorized)
        #expect(typed.reason == "Unauthorized")
    }

    @Test(".emptyToken is thrown when bearer token portion is empty")
    func emptyTokenError() async throws {
        let result = try await runThroughMiddleware(authorization: "Bearer ")
        guard case .failure(let error) = result else {
            Issue.record("expected failure, got \(result)")
            return
        }
        // Vapor's bearerAuthorization parser treats "Bearer " (no value)
        // as no token at all -> .missingToken. Either typed case is a
        // valid representation of "no usable token".
        let typed = error as? BearerTokenAuthServerError
        #expect(typed == .missingToken || typed == .emptyToken)
    }

    @Test(".oversizedToken is thrown when token exceeds maxTokenLength")
    func oversizedTokenError() async throws {
        let big = String(repeating: "x", count: 32)
        let result = try await runThroughMiddleware(
            maxTokenLength: 16,
            authorization: "Bearer \(big)"
        )
        guard case .failure(let error) = result,
              let typed = error as? BearerTokenAuthServerError else {
            Issue.record("expected BearerTokenAuthServerError, got \(result)")
            return
        }
        #expect(typed == .oversizedToken(maxLength: 16))
    }

    @Test(".invalidJWTShape is thrown by jwtShape on malformed token")
    func invalidJWTShapeError() async throws {
        let result = try await runThroughMiddleware(
            validation: .jwtShape,
            authorization: "Bearer notjwt"
        )
        guard case .failure(let error) = result,
              let typed = error as? BearerTokenAuthServerError else {
            Issue.record("expected BearerTokenAuthServerError, got \(result)")
            return
        }
        #expect(typed == .invalidJWTShape)
    }

    @Test(".invalidUUIDShape is thrown by uuidShape on malformed token")
    func invalidUUIDShapeError() async throws {
        let result = try await runThroughMiddleware(
            validation: .uuidShape,
            authorization: "Bearer not-a-uuid"
        )
        guard case .failure(let error) = result,
              let typed = error as? BearerTokenAuthServerError else {
            Issue.record("expected BearerTokenAuthServerError, got \(result)")
            return
        }
        #expect(typed == .invalidUUIDShape)
    }
}
