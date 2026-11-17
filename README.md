# @browsercore/testing


[![npm version](https://img.shields.io/npm/v/@browsercore/testing)](https://www.npmjs.com/package/@browsercore/testing)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-testing/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-testing/actions/workflows/ci.yml)

Protocol verification: RFC compliance tests, browser golden packet captures,
integration tests, and benchmarking. In short, it compares what our packages put
on the wire against what real browsers actually put there. Nothing in this
package ever runs in production, it just keeps the ones that do honest.

## Responsibility

Verify that the protocol stacks produce byte-identical output to real browsers
(RFC compliance) and measure their performance (benchmarking). Depends on every
other `@browsercore/*` package but is NOT required by them. It's purely a test/QA tool.

## What it does

The full specification lives in [`docs/TEST-SUITE.md`](../../docs/TEST-SUITE.md),
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

- **Golden packet testing**: load `.bin` captures recorded from real browsers
  (Chrome 140 (tls, http2), Firefox 128 (tls)) and compare our generated TLS
  ClientHellos, HTTP/2 SETTINGS/HEADERS frames, etc. against them. Safari 18,
  Edge 140, and Firefox 135 captures are not yet collected.
- **RFC compliance**: run focused test suites for TLS 1.3 (RFC 8446), HTTP/2
  (RFC 9113), HTTP/1.1 (RFC 9110). These are currently stubs that throw.
- **Benchmarking**: measure handshake latency and request throughput at
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

// Run the TLS RFC compliance suite (stub, throws until implemented):
// const tlsResult = runTlsCompliance();
// console.log(tlsResult.pass);

// Benchmark a TLS handshake over 100 iterations (stub, throws until implemented):
// const stats = benchmarkTlsHandshake(100);
// console.log("p99:", stats.p99, "ms");

// Fingerprint a ClientHello and an HTTP/2 connection (Cat 4):
import { computeJa3, buildAkamaiFingerprint } from "@browsercore/testing";
const ja3 = computeJa3(clientHelloBytes);
const akamai = buildAkamaiFingerprint({
    settings: [{ id: 1, value: 65536 }],
    windowUpdateIncrement: 15663105,
    priorityFrameCount: 0,
    pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
});
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
| `computeJa3()` | function | JA3 TLS ClientHello fingerprint digest |
| `computeJa4()` | function | JA4 four-part TLS ClientHello fingerprint tag |
| `buildAkamaiFingerprint()` | function | Akamai HTTP/2 fingerprint string from connection params |
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

`@browsercore/testing` sits at the very top: it depends on everything and nothing
depends on it.

## Stack versions

The suite runs against the **platform-v2 stack**: a canonical `Clock` and the
optional `Platform` / engine-injection surface defined in
[`@browsercore/contracts`](https://github.com/jverneuer/browsercore-contracts)
and assembled by [`browsersmith`](https://github.com/jverneuer/browsersmith),
the composition root. Runtime capabilities (events, TCP, DNS, crypto,
compression, time) are injected through the `Platform` object rather than
reached from the protocol layers, so every stack under test stays deterministic
and fake-friendly. Platform-v2 was a type/wiring/injection change only:
nothing wire-visible moved, and golden captures plus emission expectations
carry over unchanged.

| Package | Version |
| --- | --- |
| `@browsercore/contracts` | 0.2.7 |
| `@browsercore/transport` | 0.2.10 |
| `@browsercore/crypto` | 0.2.7 |
| `@browsercore/tls` | 0.4.17 |
| `@browsercore/http1` | 0.2.6 |
| `@browsercore/http2` | 0.2.14 |
| `@browsercore/profiles` | 0.2.6 |
| `@browsercore/cookies` | 0.2.3 |
| `@browsercore/compression` | 0.2.2 |
| `@browsercore/fetch` | 0.2.25 |

## Contributing

Contributions are welcome: bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-testing/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
