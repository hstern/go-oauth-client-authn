# Contributing

Thanks for your interest in `go-oauth-client-authn`. This is a small,
standards-focused library; contributions that improve wire fidelity, test
coverage, or documentation are especially welcome.

## Requirements

- Go 1.26 or newer.
- [`golangci-lint`](https://golangci-lint.run) for the lint step.

## Local checks

Run `make check` before opening a pull request. It runs the same steps CI
does, in order: gofmt, `go vet`, `go build`, the race-enabled test suite, and
`golangci-lint`. The equivalent `go` commands directly:

```sh
gofmt -l .                 # must print nothing
go vet ./...
go build ./...
go test -race ./...
golangci-lint run ./...
```

## Pull requests

- Branch off `main` and open a pull request; changes land via PR, not direct
  push to `main`.
- `main` is protected. The required status checks — **static**, **test**, and
  **lint** — must be green, and the branch must be up to date with `main`
  before it can merge.
- Keep each pull request focused. A logical unit of work per PR keeps review
  tractable.

## Conventions

- **Runtime dependencies are the standard library only.** The single
  sanctioned exception is [`go-jose/go-jose/v4`](https://github.com/go-jose/go-jose),
  used by the JWT assertion methods. Adding any other runtime dependency needs
  to be discussed first.
- **Tests use the standard `testing` package** with table-driven cases. Prefer
  `httptest` for HTTP-facing tests.
- **Every Go source file**, including tests, begins with the two-line
  Apache-2.0 SPDX header:

  ```go
  // Copyright 2026 The go-oauth-client-authn Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- **Commit messages are detailed.** Use an imperative subject line (≤72
  characters, no trailing period) and a body that explains why the change
  exists — the constraint satisfied, the spec clause honored, or the bug
  fixed. Cite public references (RFC numbers, spec sections) where relevant.

## Reporting security issues

Please do not file public issues for security vulnerabilities. Report them
privately through this repository's
[GitHub Security Advisories](https://github.com/hstern/go-oauth-client-authn/security/advisories)
so the maintainers can investigate and prepare a fix before disclosure.

## License

This project is licensed under the [Apache License 2.0](LICENSE). By
contributing, you agree that your contributions are licensed under the same
terms. No separate CLA or DCO sign-off is required.
