# AGENTS Instructions for GitHub Courier

These are the default rules for automated coding agents in this repository.

## 1) Scope and assumptions

- This is a Go CLI service that syncs HashiCorp Vault events and KV content from
  a source Vault to destination Vault endpoints.
- Prefer minimal, behavior-preserving changes unless the request explicitly asks
  for behavior changes.
- Follow existing patterns in each package first; avoid speculative refactors.
- Keep edits bounded to the requested outcome and avoid touching unrelated files.

## 2) Repository map

- `main.go`: process entrypoint.
- `cmd/`: Cobra commands and config wiring (flags, env handling, setup flow).
- `pkg/vault/`: Vault client and sync logic.
- `pkg/auditserver/`: UDP audit parsing, matcher integration, dedupe,
  dispatcher, and sync dispatch.
- `configs/docker/`: local sandbox and dockerized developer environment.
- `.github/workflows/`: CI, coverage, and scan config.

## 3) Build commands

- `go build ./...`
  - Compile all packages.
- `go build -v ./...`
  - Verbose compile output for diagnosing package-level failures.
- `GOOS=linux GOARCH=amd64 go build -o configs/docker/courier .`
  - Cross-compile for docker sandbox.
- `go test -c`
  - Compile tests as an additional build check.

## 4) Test commands

- `go test ./...`
  - Full suite.
- `go test -v ./...`
  - Full suite with verbose output.
- `go test -count=1 ./...`
  - Disable cache for deterministic re-runs.
- `go test -race ./...`
  - Race detector run.
- `go test -run TestNonExistent -v ./...`
  - Fast harness smoke check.
- `go test -coverprofile=coverage.out ./...`
  - Coverage output.
- `go test -coverpkg=./... ./... -race -coverprofile=coverage.out -covermode=atomic`
  - CI-style coverage command used by `ci.yml`.

## 5) Single test commands (required for focused work)

- `go test ./pkg/vault -run TestNewVaultClient -v`
- `go test ./cmd -run '^TestSplitAndTrim$' -v`
- `go test ./pkg/auditserver -run '^TestAuditServer_.*' -v`
- `go test ./pkg/auditserver -run '^TestDispatcher_.*' -v`
- `go test ./... -run TestVaultSyncer_WriteToDestinations -count=1`
- `go test ./pkg/auditserver -run '^TestAuditServer_OnTraffic$' -v`
- `go test ./pkg/auditserver -run '^Test.*JSON.*' -count=1 -v`

Use narrow package-level filters before full-suite checks.

## 6) Lint and static checks

- `gofmt -w <files>`
  - Required before finalizing edits.
- `gofmt -w -s <files>`
  - Optional simplification pass.
- `go fmt ./...`
  - Formatting pass on all packages.
- `go vet ./...`
  - Static vet checks.
- `go list ./...`
  - Module/package graph diagnostics.

## 7) Recommended verification order

1. Run focused `go test -run` in the changed package.
2. Run `go test ./...`.
3. Run `go vet ./...`.
4. Run `go build ./...`.
5. Re-run the focused test once broader checks pass.

## 8) Import and formatting style

- Keep files gofmt-compatible.
- Import groups:
  - standard library
  - third-party and internal
- Use blank lines between groups.
- Keep imports sorted and minimal.
- Avoid wildcard imports.
- Add aliases only when required (collision or readability reason).

## 9) Naming and code structure

- Exported identifiers: `PascalCase`.
- Unexported identifiers: `camelCase`.
- Interface names: noun or `-er` style (`SyncHandler`, `EventMatcher`).
- File names: snake_case (`server.go`, `server_test.go`, `dispatcher.go`).
- Keep types close to behavior and keep helper types package-local when only used in tests.
- Prefer explicit structs for shared models instead of anonymous maps.

## 10) Error handling

- Return errors from reusable/library code.
- In command paths, fail fast and log actionable context.
- Use context-wrapped errors for key boundaries, e.g. `fmt.Errorf("...: %w", err)`.
- Avoid silently discarding parse/network errors; surface or log clearly.
- Do not over-wrap; preserve root cause visibility.

## 11) Logging

- Use `log/slog` with key-value fields.
- Suggested levels:
  - `Info`: operational milestones.
  - `Error`: failures and recovery actions.
  - `Debug`: detailed internal details.
- Loggers should be passed in constructors where practical.
- Keep field keys stable for alert/search consistency.

## 12) Concurrency and channels

- Use bounded channel capacities for asynchronous work queues.
- Guard shared mutable state with explicit synchronization.
- In tests, use deterministic assertions with time-bounded waits.
- Prefer short, bounded loops rather than sleeps where possible.

## 13) Testing style and assertions

- Keep tests in `*_test.go` in matching package unless clear external behavior
  requires `package X_test`.
- Use table-driven tests for many cases.
- Use `t.Run(...)` for each logical variant.
- Use `testing` + `testify` (`assert`, `require`) consistently.
- For async behavior, assert channel/state outcomes with explicit timeout guards.

## 14) High-risk behavior areas

- CLI flag names and Viper keys (`vault.source.*`, `vault.destinations.*`).
- Destination fan-out mapping and token/address alignment.
- Dispatcher dedupe and dead-letter behavior under backpressure.
- Audit JSON parsing and matcher/filter logic.
- Resolver path for update/create/delete event kinds.

## 15) Dependency and module hygiene

- Favor existing dependencies and avoid new ones unless justified.
- For dependency changes:
  - run package tests first,
  - run `go mod tidy` only if required,
  - keep module churn scoped.
- Do not leave inconsistent `go.sum` entries.

## 16) Cursor / Copilot rule check

- `.cursor/rules/` was checked and is not present.
- `.cursorrules` was checked and is not present.
- `.github/copilot-instructions.md` was checked and is not present.

If any of these are added later, follow them as higher-priority local rules.

## 17) Commit and handoff checklist

- `gofmt` changed files.
- Add/update tests for behavior changes.
- Run at least one focused test and full validation.
- Run `go test ./...`, `go vet ./...`, `go build ./...`.
- Verify `git diff` only contains expected files.
- Note verification commands/results in the final response.

## 18) Useful references

- `.github/workflows/go.yml` for base build/test behavior.
- `.github/workflows/ci.yml` for race+coverage coverage flow.
- `README.md` for operational usage and verification notes.
- `configs/docker/` for sandboxed environment expectations.

## 19) Commit message style

- Use concise imperative phrasing, e.g.
  - `Migrate audit handling to matcher API`
  - `Fix invalid audit JSON behavior`
- Keep commits scoped to one logical purpose.

## 20) Required verification reporting in final response

- Include at least:
  - `go test ./...`
  - `go vet ./...`
  - `go build ./...`

Mention outcomes explicitly so downstream agents can trust completion state.
