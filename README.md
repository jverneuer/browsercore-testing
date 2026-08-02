# @browsercore/testing


[![npm version](https://img.shields.io/npm/v/@browsercore/testing)](https://www.npmjs.com/package/@browsercore/testing)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-testing/main/coverage/badge.json)](https://github.com/jverneuer/browsercore-testing/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-testing/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-testing/actions/workflows/ci.yml)

Protocol verification — RFC compliance tests, browser golden packet captures,
integration tests, and benchmarking. Compares generated packets against
captures from real browsers.

## Responsibility

Verify that the protocol stacks produce byte-identical output to real browsers
(RFC compliance) and measure their performance (benchmarking). Depends on every
other `@browsercore/*` package but is NOT required by them — purely a test/QA tool.

## What it does

The full specification is in [`docs/TEST-SUITE.md`](../../docs/TEST-SUITE.md) —
17 test categories, layered from unit checks up through real-world
interoperability:

| # | Category | Layer |
| --- | --- | --- |
| 1 | TCP Transport | unit / loopback |
| 2 | TLS Serialization | serialization |
| 3 | Browser Profile Comparison | golden |
| 4 | TLS Fingerprint | serialization |
| 5 | HTTP/1.1 | RFC compliance |
| 6 | HTTP/2 | serialization |
| 7 | Header Profiles | golden |
| 8 | Cookie Behavior | unit |
| 9 | Compression | unit |
| 10 | Redirect Handling | unit |
| 11 | Session Resumption | serialization |
| 12 | Connection Reuse | unit |
| 13 | Error Handling | unit |
| 14 | Packet Capture Comparison | golden / reference |
| 15 | Real World Compatibility | reference |
| 16 | Regression Tests | unit |
| 17 | Performance Benchmarks | benchmark |

In short:

- **Golden packet testing** — load `.bin` captures recorded from real browsers
  (Chrome 140 (tls, http2), Firefox 128 (tls)) and compare our generated TLS
  ClientHellos, HTTP/2 SETTINGS/HEADERS frames, etc. against them. Safari 18,
  Edge 140, and Firefox 135 captures are not yet collected.
- **RFC compliance** — run focused test suites for TLS 1.3 (RFC 8446), HTTP/2
  (RFC 9113), HTTP/1.1 (RFC 9110). These are currently stubs that throw.
- **Benchmarking** — measure handshake latency and request throughput at
  p50/p95/p99. These are currently stubs that throw.

## Public API

```ts
import {
    compareAgainstGolden,
    runTlsCompliance,
    benchmarkTlsHandshake,
    GoldenMismatchError,
} from "@browsercore/testing";

// Compare our ClientHello against a Chrome 140 capture:
const result = compareAgainstGolden(myClientHello, "chrome-140:client-hello:1" as never);
console.log(result.matches);

// Run the TLS RFC compliance suite (stub — throws until implemented):
// const tlsResult = runTlsCompliance();
// console.log(tlsResult.pass);

// Benchmark a TLS handshake over 100 iterations (stub — throws until implemented):
// const stats = benchmarkTlsHandshake(100);
// console.log("p99:", stats.p99, "ms");
```

## Types

| Export | Kind | Purpose |
| --- | --- | --- |
| `compareAgainstGolden()` | function | Compare bytes against a golden capture |
| `loadGolden()` | function | Load a golden capture by id |
| `runTlsCompliance()` | function | TLS RFC 8446 compliance suite |
| `runHttp2Compliance()` | function | HTTP/2 RFC 9113 compliance suite |
| `runHttp1Compliance()` | function | HTTP/1.1 RFC 9110 compliance suite |
| `benchmarkTlsHandshake()` | function | TLS handshake benchmark |
| `benchmarkHttp2Request()` | function | HTTP/2 request benchmark |
| `GoldenCapture` | interface | A recorded packet capture |
| `ComparisonResult` | interface | Outcome of a golden comparison |
| `BenchStats` | interface | p50/p95/p99 latency stats |

## Dependency graph

```
@browsercore/testing
  └─ @browsercore/fetch  @browsercore/http2  @browsercore/http1  @browsercore/cookies
        └─ @browsercore/profiles  @browsercore/tls  @browsercore/crypto
              └─ @browsercore/transport
                    └─ node:net / node:crypto
```

`@browsercore/testing` sits at the very top — it depends on everything and nothing
depends on it.
