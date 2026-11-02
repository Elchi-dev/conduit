# ADR 0003: Hand-written handlers checked against the spec; server-sent events

- Status: accepted
- Date: 2026-11-03

## Context

The plan called for OpenAPI-first code generation for both server and
clients, and WebSockets for live events.

## Decision

- `api/openapi/*.yaml` stays the source of truth. The TypeScript client is
  generated from it. Go handlers are written by hand, and a test
  (`TestRoutesMatchOpenAPI`) fails if a served route is undocumented or a
  documented route is not served.
- Live events use server-sent events (`GET /api/v1/events`), not WebSockets.

## Consequences

- Server code stays plain `net/http` with no generated layers to read
  through, while the spec cannot silently drift from the routes.
- Request/response shapes are not compile-checked against the spec on the Go
  side; API tests cover them.
- SSE needs no dependency, works through HTTP proxies and the hub relay, and
  reconnects automatically in browsers. Events only flow one way, which is all
  the UI needs; commands go over normal requests.
