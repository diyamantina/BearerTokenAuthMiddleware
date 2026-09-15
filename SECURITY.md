# Security Policy

## Reporting a vulnerability

If you believe you have found a security issue in BearerTokenAuthMiddleware,
please report it privately. Do not open a public issue for security problems.

Email **mihaelamj@gmail.com** with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected version or commit.

You can expect an acknowledgement within a few days. Once the issue is confirmed,
a fix will be prepared and a release cut, after which the issue can be disclosed
publicly with credit to the reporter if desired.

## Supported versions

Security fixes are applied to the latest `2.x` release and to the `main` branch.
Older versions are not maintained; upgrade to the latest release to receive
fixes.

## Scope

BearerTokenAuthMiddleware ships a client-side header stamper and a
server-side Vapor middleware that enforces bearer tokens. In scope:

- Any way the client middleware attaches or omits the `Authorization` header
  incorrectly, including the `skipAuthorization` operation list.
- Incorrect enforcement in `BearerTokenAuthServerMiddleware`, including
  `publicEndpoints` / `publicPathPrefixes` matching that lets an unauthenticated
  request reach a protected handler, or the reverse.
- Weaknesses in the built-in shape validators (`.jwtShape`, `.uuidShape`) that
  accept a malformed or forged token as well-formed.
- Any way `BearerTokenContext`'s task-local token leaks from one request into
  another request's handler.

Out of scope: `.jwtShape` and `.uuidShape` are intentionally shape-only and do
not verify signatures, claims, or session validity. Applications that need real
verification must supply a `.custom` validator; a bypass of shape-only checks
via an unsigned but well-formed token is expected behavior, not a
vulnerability.
