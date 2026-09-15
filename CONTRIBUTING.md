# Contributing to BearerTokenAuthMiddleware

Thanks for your interest in BearerTokenAuthMiddleware. This guide covers how to
set up, the conventions the project follows, and how to land a change.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

BearerTokenAuthMiddleware is a single Swift package with two products,
`BearerTokenAuthMiddleware` (client) and `BearerTokenAuthServerMiddleware`
(Vapor server). You need a Swift 6.0 toolchain (Xcode 16+ on Apple platforms, or
the official Swift 6.0 container on Linux). From the repo root:

```sh
swift build
swift test
```

CI runs a five-platform matrix (`.github/workflows/test.yml`): full build and
test on Linux and macOS, and client-product-only build verification on iOS,
tvOS, and watchOS simulators, since `BearerTokenAuthServerMiddleware` depends on
Vapor and Vapor does not ship for those platforms.

## Conventions

- **Swift 6 strict concurrency** is on. Types crossing concurrency boundaries are
  `Sendable`; prove it rather than silencing with `@unchecked`.
- **Make impossible states unrepresentable.** No force-unwrapping (`!`, `try!`) in
  shipping code.
- **Testable by design.** Test behaviour through the public API, not
  implementation details.
- **Cross-platform.** Keep client-product code free of Darwin-only APIs so it
  keeps building for iOS/tvOS/watchOS; server-product code may depend on Vapor.
- Read the surrounding files before writing new code and match what is already
  there. Consistency with existing code outranks personal preference.

## Tests

Tests use the **Swift Testing** framework (`@Test`, `@Suite`, `#expect`), not
XCTest. One behaviour per test, descriptive names, deterministic data, no live
network. Add coverage for any behaviour you change, especially around
`ValidationStrategy`, `publicEndpoints`/`publicPathPrefixes` matching, and
`BearerTokenContext` task-local propagation.

Run `swift test` and confirm the suite passes before opening a PR.

## Commits

Commit messages follow Conventional Commits: `<type>(<scope>): summary`, lowercase
type, imperative mood, no trailing period, first line under 72 characters. Types:
`feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`,
`chore`.

## Branches

Branch from the current tip of `main`:

```sh
git fetch origin main && git checkout -b feat/<topic> origin/main
```

Naming: `fix/<issue>-<topic>`, `feat/<topic>`, `chore/<topic>`, `docs/<topic>`,
`refactor/<topic>`.

## Pull requests

- One focused change per PR. If the diff spans two unrelated concerns, split it.
- Run `swift build` and `swift test` and confirm both pass before opening the PR.
- Do a self-review pass on your own diff and fix what a reviewer would flag.

## Issues

For bugs, file an issue first describing the symptom, the expected behaviour, and
a reproduction, then branch with the issue number in the name. For features, an
issue is recommended when the scope is non-trivial.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
