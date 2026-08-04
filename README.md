# @browsercore/testing

[![npm version](https://img.shields.io/npm/v/@browsercore/testing)](https://www.npmjs.com/package/@browsercore/testing)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-testing/main/coverage/badge.json)](https://github.com/jverneuer/browsercore-testing/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-testing/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-testing/actions/workflows/ci.yml)

Protocol verification — golden packet captures from real browsers, JA3/JA4
fingerprint computation, a pluggable reference-provider layer, a Node.js
reference oracle for the primitive layers, RFC compliance suites, and
benchmarking. Depends on every other `@browsercore/*` package but is NOT
required by them — purely a test/QA tool.

## Responsibility

Verify that the protocol stacks produce byte-identical output to real browsers
(golden comparison), that derived fingerprints match the expected JA3/JA4
tags, and — eventually — that they conform to the relevant RFCs and meet
performance targets. The package is layered so cheap deterministic checks run
on every push and expensive, network-dependent checks run on demand / in CI.

## What it does

The implementation is tracked against a 17-category test model (see the
Implementation Plan, `PLAN.md`). As of this writing, the deterministic core is
shipped and the network-dependent and specification suites are stubbed:

**Implemented (shipped):**

- **Golden packet testing** — load `.bin` captures recorded from real browsers
  (Chrome 140 (tls, http2), Firefox 128 (tls)) via `loadGolden()` and compare
  our generated TLS ClientHellos, HTTP/2 SETTINGS frames, etc. against them
  with `compareAgainstGolden()`. A tolerant variant,
  `compareAgainstGoldenWithIgnore()`, masks the byte ranges the protocol
  intentionally randomizes (ephemeral keys, nonces, GREASE, client_random) —
  the core mechanism behind Category 14.
- **Fingerprint computation** — `computeJa3()`, `computeJa4()`,
  `computeJa4Fingerprint()`, and `computeJa4h()` parse a ClientHello and emit
  the canonical tags (Category 4).
- **Reference-provider layer** — a pluggable facade over a PRIMARY
  curl-impersonate provider, a SECONDARY real-browser provider (pre-recorded
  captures), and a `ReferenceProviderFacade` that tries the primary first and
  falls back to the secondary (Categories 3, 14, 15).
- **Node.js reference oracle** — `nodeCrypto`, `nodeDns`, `nodeZlib`, and
  `nodeHttp` wrap Node's built-in implementations behind a uniform comparator
  surface so the primitive layers can be tested for equivalent observable
  behavior (the layers where Node IS the spec reference — deliberately not
  the browser-fingerprint layers).

**Stubbed (throw `"not implemented — see PLAN.md"`):**

- **RFC compliance suites** — `runTlsCompliance()` (RFC 8446),
  `runHttp2Compliance()` (RFC 9113), `runHttp1Compliance()` (RFC 9110).
- **Benchmarks** — `benchmarkTlsHandshake()` and `benchmarkHttp2Request()`
  (p50/p95/p99 latency, requests-per-second).

**Planned (`it.todo` placeholders in vitest):**

- The 17 test categories (`src/categories/`) currently hold `it.todo`
  placeholders describing the intended coverage — unit checks up through
  real-world interoperability. They are the implementation roadmap, not
  yet assertion-backed tests.

## Public API

```ts
import {
    // Golden capture loading + comparison
    loadGolden,
    loadCaptureMeta,
    compareAgainstGolden,
    compareAgainstGoldenWithIgnore,
    parseCaptureMeta,
    parseRandomizedFields,
    // Fingerprint computation
    computeJa3,
    computeJa4,
    computeJa4Fingerprint,
    computeJa4h,
    parseClientHello,
    Ja3ParseError,
    Ja4ParseError,
    // Reference providers
    createReferenceProvider,
    createReferenceFacade,
    ReferenceProviderFacade,
    CurlImpersonateProvider,
    RealBrowserCaptureProvider,
    // Node.js reference oracle
    nodeCrypto,
    nodeDns,
    nodeZlib,
    nodeHttp,
    toError,
    compareBytesOutcome,
    // RFC compliance (stub — throws until implemented)
    runTlsCompliance,
    runHttp2Compliance,
    runHttp1Compliance,
    // Benchmarks (stub — throws until implemented)
    benchmarkTlsHandshake,
    benchmarkHttp2Request,
} from "@browsercore/testing";

// Compare our ClientHello against a Chrome 140 capture (strict):
const result = compareAgainstGolden(myClientHello, "chrome-140/tls/client_hello" as never);
console.log(result.matches);

// ...or with randomized-field masking (Category 14 tolerant):
const tolerant = compareAgainstGoldenWithIgnore(myClientHello, "chrome-140/tls/client_hello" as never);
console.log(tolerant.maskedRanges);

// Derive JA3 / JA4 from a ClientHello:
const ja3 = computeJa3(myClientHello);
const ja4 = computeJa4Fingerprint(myClientHello);
console.log(ja3, ja4.tag);
```

## Types

| Export | Kind | Purpose |
| --- | --- | --- |
| `compareAgainstGolden()` | function | Strict byte comparison against a golden capture |
| `compareAgainstGoldenWithIgnore()` | function | Tolerant comparison masking randomized ranges |
| `loadGolden()` | function | Load a golden capture by id |
| `loadCaptureMeta()` | function | Load a golden capture's sidecar metadata |
| `parseCaptureMeta()` | function | Validate unknown JSON as `CaptureMeta` |
| `parseRandomizedFields()` | function | Validate unknown data as `RandomizedField[]` |
| `computeJa3()` | function | JA3 digest from a ClientHello |
| `computeJa4()` | function | JA4 parts + canonical tag from a ClientHello |
| `computeJa4Fingerprint()` | function | JA4 tag from a ClientHello |
| `computeJa4h()` | function | JA4H (HTTP-layer) fingerprint |
| `parseClientHello()` | function | Parse a ClientHello into JA3/JA4 segments |
| `runTlsCompliance()` | function | TLS RFC 8446 compliance suite (stub) |
| `runHttp2Compliance()` | function | HTTP/2 RFC 9113 compliance suite (stub) |
| `runHttp1Compliance()` | function | HTTP/1.1 RFC 9110 compliance suite (stub) |
| `benchmarkTlsHandshake()` | function | TLS handshake benchmark (stub) |
| `benchmarkHttp2Request()` | function | HTTP/2 request benchmark (stub) |
| `createReferenceProvider()` | function | Construct the provider matching a kind |
| `createReferenceFacade()` | function | Wrap both providers + node oracle |
| `ReferenceProviderFacade` | class | Primary→secondary fallback facade |
| `CurlImpersonateProvider` | class | curl-impersonate subprocess provider |
| `RealBrowserCaptureProvider` | class | Pre-recorded-capture provider |
| `nodeCrypto` / `nodeDns` / `nodeZlib` / `nodeHttp` | object | Node.js reference oracles |
| `GoldenCapture` | interface | A recorded packet capture |
| `CaptureMeta` | interface | Sidecar metadata for a capture |
| `ComparisonResult` | interface | Outcome of a golden comparison |
| `ComparisonResultWithIgnore` | interface | Outcome with masked-range reporting |
| `RandomizedField` | interface | A byte range to mask before comparison |
| `Fingerprint` | interface | Observable TLS/HTTP fingerprint |
| `BenchStats` | interface | p50/p95/p99 latency stats |
| `TestCategory` | const | The 17 test-category ids |
| `TestingError` / `GoldenMismatchError` | class | Typed errors |
| `ReferenceError` / `DumpParseError` | class | Reference-provider errors |

## Development

This package uses the shared `@browsercore/dev` build/lint/test config. The
convenience scripts are the standard ones for every `@browsercore/*` package:

```sh
npm run build        # tsc -p tsconfig.build.json (emit to dist/)
npm run typecheck    # tsc -p tsconfig.json --noEmit (type-check only, no emit)
npm run test         # vitest run
npm run test:watch   # vitest (interactive watch mode)
npm run lint         # oxlint --type-aware src/
```

Run a **single test** with vitest's file filter:

```sh
npx vitest run tests/golden.test.ts
```

Run tests by **name pattern**:

```sh
npx vitest run -t "compareAgainstGolden"
```

### Shared config (`@browsercore/dev`)

`@browsercore/dev` is the shared config package that keeps build/lint/test
settings consistent across every `@browsercore/*` repo. It is declared as a
`file:../dev` devDependency (this package is developed as part of the
monorepo alongside its siblings) and provides:

- `definePackageConfig({ name })` — a single-source vitest config. Used in
  `vitest.config.ts`, so reporter, timeout, and coverage settings stay in sync
  with the other packages.
- `oxlintBase` — the base oxlint config extended in `oxlint.config.ts`. The
  base rules live in one place; this package adds one local override (see
  "Migration status" below).
- `tsconfig.base.json` / `tsconfig.build.base.json` — the strict-mode
  tsconfig foundation (`strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`).

## Migration status

The codebase is mid-migration on one style rule:

- **`_`-prefixed identifiers:** 16 underscore-prefixed identifiers remain in
  `src/`, all of them unused-parameter markers in the stub functions
  (`_iterations`, `_options`, `_id`, `_url` in `bench.ts`, `rfcTests.ts`, and
  `browser-provider.ts`). These are NOT yet renamed to the `#private` / `private`
  convention. `oxlint.config.ts` disables `no-underscore-dangle` with a TODO
  to remove the override once the rename is done. No `_`-prefixed privates
  remain in the implemented (non-stub) code.

The RFC compliance suites and benchmarks are stubs that throw; the 17-category
vitest suites are `it.todo` placeholders. See `PLAN.md` for the phased roadmap
and definition of done.

## Dependency graph

```
@browsercore/testing
  ├─ @browsercore/fetch  @browsercore/http2  @browsercore/http1  @browsercore/cookies
  │    └─ @browsercore/profiles  @browsercore/tls  @browsercore/crypto
  │          └─ @browsercore/transport
  ├─ @browsercore/compression
  └─ (dev) @browsercore/dev  ← shared vitest / oxlint / tsconfig
```

`@browsercore/testing` sits at the very top — it depends on everything and
nothing depends on it.
