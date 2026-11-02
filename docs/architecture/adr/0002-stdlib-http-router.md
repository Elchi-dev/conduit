# ADR 0002: Standard library HTTP routing

- Status: accepted
- Date: 2026-11-03

## Context

The plan named chi as the router. Since Go 1.22, `net/http.ServeMux` supports
method and path-parameter patterns (`GET /api/v1/modules/{id}`).

## Decision

Use `net/http.ServeMux` with small middleware functions instead of chi.

## Consequences

One fewer dependency. Route patterns stay readable. If routing needs outgrow
the standard mux (e.g. route groups with per-group middleware become unwieldy),
chi is a drop-in replacement because it uses standard `http.Handler`s.
