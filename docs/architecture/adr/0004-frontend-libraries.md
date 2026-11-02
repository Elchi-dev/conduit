# ADR 0004: Small routing and styling layer for the web app

- Status: accepted
- Date: 2026-11-03

## Context

The plan named TanStack Router and vanilla-extract.

## Decision

- Routing uses `wouter` (a few kilobytes, plain path patterns).
- Styling uses plain CSS files with design tokens as CSS custom properties.
- TanStack Query, `openapi-fetch` and `cmdk` are used as planned.

## Consequences

- The app has about ten routes and no nested data loading, so a typed router
  adds build complexity without paying for itself; this can be revisited if
  routing grows.
- Tokens as custom properties switch themes at runtime with no rebuild and
  are shared by the website (phase 14).
- No compile-time checking of class names; keep CSS colocated with the
  component or page that uses it.
