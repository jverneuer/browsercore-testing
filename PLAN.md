# @browsercore/testing — Implementation Plan

Protocol verification tooling. The canonical test specification lives in
[`docs/TEST-SUITE.md`](../../docs/TEST-SUITE.md); this plan is the roadmap for
implementing it. Implement in order — each phase is independently testable.

## Phases (layered philosophy)

Tests are layered so cheap deterministic checks run on every push and
expensive, network-dependent checks run on demand / in CI:

1. **Unit** — pure helpers (byte comparison, error classes). Always run.
2. **Serialization** — golden packet comparison against recorded browsers.
3. **RFC compliance** — protocol-conformance suites (RFC 8446, 9113, 9110).
4. **Reference comparison** — compare our wire output against a reference.
5. **Real-world compatibility** — interoperability against public servers.
6. **Performance benchmarks** — latency/throughput, tracked over time.

## Phase 1 — Unit foundations (DONE)

- [x] `compareBytes` / `bytesToHex` helpers + typed errors (`errors.ts`).
- [x] Typed `TestCategory` model (17 categories) in `types.ts`.
- [x] Per-category vitest stubs in `src/categories/` with real assertions
      where trivial (error class instantiation).

## Phase 2 — Golden capture storage

Define how captures are stored on disk: a `.bin` file of raw bytes plus a
sidecar `.json` with `source`, `protocol`, `description`, and byte offsets for
sub-records. Add a registry so `loadGolden(captureId)` resolves a path.

Feeds categories: **14 (packet capture comparison)**, **2 (TLS serialization)**,
**3 (browser profile comparison)**.

## Phase 3 — TLS golden captures

Record ClientHello + TLS extensions from Chrome 140, Firefox 135, Safari 18,
Edge 140. Store as golden captures. Tests: our TLS stack's ClientHello
byte-matches the capture for a given profile.

Feeds categories: **2, 3, 4 (TLS fingerprint)**.

## Phase 4 — HTTP/2 golden captures

Record the first SETTINGS and HEADERS frames browsers send on a fresh h2
connection. Add HTTP/2 compliance tests that compare byte-for-byte.

Feeds categories: **6 (HTTP/2)**, **7 (header profiles)**.

## Phase 5 — RFC compliance suites

Implement `runTlsCompliance`, `runHttp2Compliance`, `runHttp1Compliance`:
cipher-suite ordering, extension presence, GREASE values, frame format,
HPACK encoding, chunked transfer encoding, etc. Each check returns a
`TestResult`.

Feeds categories: **2, 5 (HTTP/1.1), 6**.

## Phase 6 — Browser comparison harness

End-to-end: spin up a loopback server, run a real request through
`@browsercore/fetch`, record bytes, compare against the golden capture for the
active profile. Report divergence index + message.

Feeds categories: **3, 14**.

## Phase 7 — Cookie, compression, redirect, session, error suites

Focused suites for the mid-stack behavior categories.

Feeds categories: **8 (cookies), 9 (compression), 10 (redirects),
11 (session resumption), 12 (connection reuse), 13 (error handling)**.

## Phase 8 — Real-world compatibility harness

Drive connections against a representative set of public servers (static
sites, HTTP/2-only, CDNs, reverse proxies, TLS 1.2/1.3-only, large cert
chains). Requires network — runs on demand / in CI with care.

Feeds category: **15**.

## Phase 9 — Regression test harness

Every discovered protocol issue produces a permanent regression test with
serialized packets, expected parser output, expected state transitions, and
expected network behavior.

Feeds category: **16**.

## Phase 10 — Performance benchmarks

Implement `benchmarkTlsHandshake` and `benchmarkHttp2Request` against
loopback servers. Report p50/p95/p99 latency and requests-per-second.
Tracked over time to identify regressions.

Feeds category: **17**.

## Phase 11 — CI integration

Wire the compliance suites + golden comparisons into CI so a fingerprint
regression fails the build. Per docs/TEST-SUITE.md "Continuous Validation":
unit + serialization + RFC + packet comparison + profile validation run on
every PR; interoperability + benchmarks where practical.

## The 17 categories (implementation roadmap)

| # | Category id | Phase |
| --- | --- | --- |
| 1 | `tcp-transport` | 6 (loopback) |
| 2 | `tls-serialization` | 3, 5 |
| 3 | `browser-profile-comparison` | 3, 6 |
| 4 | `tls-fingerprint` | 3 |
| 5 | `http1` | 5 |
| 6 | `http2` | 4, 5 |
| 7 | `header-profiles` | 4 |
| 8 | `cookie-behavior` | 7 |
| 9 | `compression` | 7 |
| 10 | `redirect-handling` | 7 |
| 11 | `session-resumption` | 7 |
| 12 | `connection-reuse` | 7 |
| 13 | `error-handling` | 7 |
| 14 | `packet-capture-comparison` | 2, 6 |
| 15 | `real-world-compatibility` | 8 |
| 16 | `regression` | 9 |
| 17 | `performance-benchmarks` | 10 |

## Definition of done

- [x] `compareBytes` / `bytesToHex` + typed errors implemented and tested.
- [x] Typed `TestCategory` model with all 17 categories; per-category vitest stubs.
- [ ] `loadGolden()` reads `.bin` + `.json` captures from disk.
- [ ] TLS ClientHellos byte-match golden captures per profile.
- [ ] HTTP/2 SETTINGS/HEADERS byte-match golden captures per profile.
- [ ] All three RFC compliance suites run and report per-check results.
- [ ] Browser comparison harness reports exact divergence byte on mismatch.
- [ ] Cookie / compression / redirect / session / error suites pass.
- [ ] Real-world compatibility harness interoperates with diverse servers.
- [ ] Regression harness captures serialized packets + expected transitions.
- [ ] Benchmarks report p50/p95/p99 over a configurable iteration count.
- [ ] CI runs unit + serialization + RFC + packet + profile checks per PR.
- [ ] Every test in `tests/` passes; `tsc --build` is clean.
