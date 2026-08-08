# E2E Traffic Gate — Design Document

> Architecture for the browsercore end-to-end traffic gate: a local HTTPS
> server that returns known content, fetched through the full browsersmith
> stack, asserting the bytes round-trip intact. First version — keep it
> simple.

---

## 1. Purpose

Every existing TLS test in the stack runs against an in-process fixture
(`FakeTransport`, `TlsServerSim`). The `TlsSinkServer` performs a real TCP +
TLS handshake but only inspects the *ClientHello* — it never decrypts a
server's encrypted application-data records. **Bug 6** (AES-128-GCM record
decryption fails against real servers) lives exactly in that gap: the path
that reads an encrypted record from the wire, derives the traffic keys, and
decrypts the server's handshake flight.

The e2e traffic gate closes that gap. It exercises the *entire* stack against
a real TLS 1.3 endpoint we control:

```
local HTTPS server (known response)
        ↑ TLS 1.3 + HTTP/1.1 or HTTP/2
        |
browsersmith fetch()  (TLS → HTTP → response)
        ↑ assertion: status, body, headers match
        |
gate test (vitest)
```

If the record layer can't decrypt the server's flight, the fetch fails — the
gate catches Bug 6 deterministically, without external network access.

---

## 2. Server Design

### 2.1 What kind of HTTPS server?

A **`node:https.createServer`** (or `node:http2.createSecureServer`) backed by
the existing `generateSelfSignedCert()` ECDSA P-256 certificate from
`src/e2e/cert-gen.ts`.

- **Self-signed, not public-CA.** The gate runs locally in CI; a throwaway
  self-signed cert is correct. The client is configured with
  `rejectUnauthorized: false` (exactly as the existing `sink-server.test.ts`
  already does for its own TLS handshakes).
- **ECDSA P-256, not RSA.** Real servers browsersmith impersonates against use
  ECDSA. Matching the cert type exercises the same code paths (signature
  algorithm negotiation, certificate verification) that a real deployment does.
- **ALPN: `["h2", "http/1.1"]`.** The gate negotiates the protocol the same
  way the production stack does. We run the test matrix over both: one case
  forces HTTP/2, one allows HTTP/1.1.

### 2.2 What does it return?

A **known JSON body** with a fixed shape, plus a deterministic set of
response headers. The client asserts every field.

```json
{
  "ok": true,
  "protocol": "h2",
  "method": "GET",
  "path": "/gate",
  "server": "browsercore-e2e-gate",
  "timestamp": "2026-08-08T00:00:00.000Z"
}
```

- The `timestamp` is injected by the server at request time; the client
  asserts it is within a few seconds of `Date.now()` (liveness check).
- The `protocol` field reflects the negotiated ALPN protocol the server
  observed — this is a cross-check that the client and server agree on which
  protocol is on the wire (HTTP/2 vs HTTP/1.1).
- A `GET /echo-headers` path returns the received header names in arrival
  order, so the gate can also assert that the profile's header ordering made
  it onto the wire (complements the bot-detection fixture in browsersmith).

### 2.3 Endpoints

| Path            | Status | Body                                              |
|-----------------|--------|---------------------------------------------------|
| `GET /gate`     | 200    | Known JSON (`ok: true`, `protocol`, `timestamp`)  |
| `GET /echo-hdrs`| 200    | JSON `{ "headers": [[name, value], ...] }`        |
| any other       | 404    | `{ "error": "not found" }`                        |

The server is single-purpose and tiny (~80 lines). It is **not** a general
fixture — it exists only for this gate.

---

## 3. Client Design

### 3.1 How does browsersmith connect?

The test imports `fetch` and `createClient` from `browsersmith` and the
platform adapters (`nodeNet`, `nodeDns`) it wires up. The flow:

```ts
import { fetch } from "browsersmith";
import { nodeNet, nodeDns } from "browsersmith";

const response = await fetch(`https://127.0.0.1:${port}/gate`, {
  profile: "chrome-140",
  // browsersmith forwards these to the Node TLS adapter:
  rejectUnauthorized: false,  // accept the self-signed cert
  net: nodeNet,
  dns: nodeDns,
});
```

Two important points:

1. **We use `browsersmith`, not `@browsercore/fetch` directly.** browsersmith
   is the composition root that wires `nodeNet`/`nodeDns` into the transport
   layer (`src/wiring.ts` → `setConnectorDeps`). Without that wiring, the
   fetch client cannot open real TCP connections — it silently no-ops or
   throws "no transport". The existing `e2e-detection.test.ts` in browsersmith
   goes through `loopbackTransportFactory` (a fake socket); this gate goes
   through the *real* `node:net` path, which is the whole point.

2. **`rejectUnauthorized: false` must propagate.** The fetch client passes
   TLS options down through `pool.ts` → `tls-adapter.ts` → `@browsercore/tls`.
   This is the same option the existing sink tests pass to `node:tls.connect`.
   If it fails to propagate, the gate fails with a certificate error — a
   different, but still valid, signal.

### 3.2 Which profile?

The gate runs against **chrome-140** as the primary case. This is the
canonical profile in `browsersmith/src/profiles.ts` and the one with the most
real-world golden captures. A second case runs **firefox-128** to prove the
gate is profile-independent (catches profile-specific key-derivation bugs).

| Case            | Profile     | Negotiated protocol |
|-----------------|-------------|---------------------|
| chrome-h2       | chrome-140  | h2                  |
| chrome-h1       | chrome-140  | http/1.1            |
| firefox-h2      | firefox-128 | h2                  |

The protocol is pinned via the client's `ALPNProtocols: ["h2"]` or
`ALPNProtocols: ["http/1.1"]` (overriding the default `["h2","http/1.1"]`).
The server picks the first protocol it supports from the client's offer.

### 3.3 What do we assert?

The gate asserts, in order:

1. **Status is 200.** If the handshake or record decryption failed, the
   fetch never completes — the promise rejects with a `FetchError` /
   `ProtocolError`.

2. **Body parses as JSON** with `ok: true` and the expected `server` field.
   This proves the response bytes were decrypted and decompressed correctly.

3. **`protocol` in the body matches the client's negotiated protocol.**
   Cross-check: the server reports what it saw on the wire; the client
   reports what ALPN selected. They must agree. (We read the negotiated
   protocol from `response.headers` or a client-side accessor.)

4. **`timestamp` is within 10 seconds of `Date.now()`.** Liveness — proves the
   body wasn't served from a cache or replay.

5. **(h2 only) The fetch actually used HTTP/2.** Assert via the response's
   effective protocol, or by checking the server-side log recorded an h2
   session. This pins the case: we aren't accidentally negotiating HTTP/1.1
   and still passing.

Failure modes and what they mean:

| Failure                          | Likely cause                       |
|----------------------------------|------------------------------------|
| `FetchError: TLS handshake...`   | ClientHello rejection, ALPN mismatch |
| `ProtocolError: record layer...` | **Bug 6 — decryption failure**     |
| `FetchTimeoutError`              | Hang in the record/read loop       |
| Body mismatch                    | Decompression or framing bug       |
| `protocol` mismatch              | ALPN negotiation regression        |

---

## 4. Bug 6 Reproduction

Bug 6 manifests as: the handshake key exchange succeeds, the handshake
traffic secrets are derived, but the first encrypted server record
(EncryptedExtensions) fails AES-128-GCM decryption with "authentication
mismatch or corrupt input".

**Why the gate catches it:**

The HTTPS server sends its *entire response* — status line, headers, body —
as encrypted TLS application-data records. For the fetch to return a 200 with
a JSON body, the record layer must successfully decrypt **multiple** server
records (not just the first handshake message). If the key derivation, nonce
construction, or AEAD decryption is wrong, the response can never be
assembled, and the gate fails.

**Specifically, the gate exercises the path that Bug 6's "hypothesis C"
(transcript bytes used for key derivation differ from what the server
encrypted against) would break:**

1. The client sends a ClientHello (the same bytes chrome-140 always sends).
2. The server replies with ServerHello + ChangeCipherSpec + encrypted
   EncryptedExtensions + Certificate + CertificateVerify + Finished — all
   encrypted under the handshake traffic key.
3. The client (`@browsercore/tls` handshake-messages.js) reads each record,
   decrypts it with the derived handshake traffic key, and reassembles the
   handshake transcript.
4. Then it derives the *application* traffic key and decrypts the actual
   HTTP response records.

If step 3 fails → `ProtocolError: decryption failed` → gate red.
If step 4 fails → same.
If step 3 succeeds but the key was wrong *in a way that happens to decrypt*
→ the transcript hash wouldn't match the server's, the Finished verify_data
would fail, and the handshake aborts before any application data. So the
gate is robust: it doesn't just pass on *a* decryption, it passes only on
the *correct* decryption through the full handshake.

**Determinism:** The gate runs against a local server with a pinned cipher
suite preference (TLS_AES_128_GCM_SHA256 for chrome-140). There is no network
flakiness, no CDN variation, no clock skew (we assert our own liveness). A
fail is always a real regression.

---

## 5. CI Integration

### 5.1 How does it run?

The gate is a standard vitest test file in `tests/e2e/`:

```
browsercore-testing/
  tests/e2e/traffic-gate.test.ts     ← the gate
```

It runs as part of the existing `npm test` (vitest run) on every PR. No
separate workflow needed for v1 — the existing CI already runs vitest.

### 5.2 Node version requirement

The gate requires **Node >= 26** (matching the existing `engines` field in
package.json) because it uses `generateSelfSignedCert` which relies on
`generateKeyPairSync({ namedCurve: "P-256" })` — available in all supported
versions. CI already runs Node 26+ for this package.

### 5.3 Self-signed cert in CI

No extra setup. The cert is generated at test time in-process by
`generateSelfSignedCert` (already used by `TlsSinkServer` in CI today). There
is no cert file to check in, no trust store to configure. The client passes
`rejectUnauthorized: false`.

### 5.4 GitHub Actions workflow (when we add a dedicated one)

```yaml
# .github/workflows/browsercore-e2e-gate.yml
name: E2E Traffic Gate
on:
  pull_request:
    branches: [main]
    paths:
      - 'basement/browsercore-*/**'
      - 'basement/browsersmith/**'
      - 'basement/browsercore-testing/**'
jobs:
  e2e-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 26 }
      - run: npm ci --legacy-peer-deps
      - run: cd basement/browsercore-testing && npm run build && npm test
```

For v1 we **do not** add a dedicated workflow. The gate ships as a test file
in the existing suite and rides the existing CI. A dedicated workflow is a v2
optimization (separate badge, faster signal, parallel job).

### 5.5 Triggers on every PR to main

No version-bump detection, no path filtering beyond the existing CI's
default. Simpler to run on every PR. If runtime becomes a problem (>30s),
add a path filter later.

---

## 6. File Layout

Exact files added to `browsercore-testing/`:

```
browsercore-testing/
  src/e2e/
    traffic-server.ts        ← NEW: the local HTTPS server class
  tests/e2e/
    traffic-gate.test.ts     ← NEW: the gate tests (chrome-h2, chrome-h1, firefox-h2)
  docs/
    E2E-TRAFFIC-GATE.md      ← THIS FILE: design + rationale
```

### 6.1 `src/e2e/traffic-server.ts`

```ts
// Responsibilities:
// - start({ alpnProtocols }) → TrafficServer   (ephemeral port, self-signed cert)
// - HTTPS server with the three endpoints in §2.3
// - Records the negotiated protocol per request (for cross-check assertion)
// - stop() → Promise<void>
// - Exposes host, port

export interface TrafficServer {
  readonly host: string;       // "127.0.0.1"
  readonly port: number;       // ephemeral
  stop(): Promise<void>;
}
export class TrafficServer { ... }
```

Reuses `generateSelfSignedCert` from `src/e2e/cert-gen.ts` (already
battle-tested by `TlsSinkServer`). Implemented over `node:https` with
ALPN configured on the secure context.

### 6.2 `tests/e2e/traffic-gate.test.ts`

```ts
// Three test cases, one per row in the matrix (§3.2).
// Each case:
//   1. start TrafficServer
//   2. browsersmith fetch() → 127.0.0.1/gate with the profile + pinned ALPN
//   3. assert status, body, protocol match, liveness
//   4. stop server
//
// Uses describe.each over the matrix to keep it flat and obvious.
```

Imports from `browsersmith` (the real entrypoint) and the platform adapters.
Uses the existing `suppressSocketErrors` helper pattern from
`sink-server-coverage.test.ts` where appropriate (not strictly needed for
HTTPS, since the server is well-behaved, but defensive on teardown).

### 6.3 Why `browsercore-testing` and not `browsersmith/testing/`?

- `browsercore-testing` already has the e2e infrastructure (`TlsSinkServer`,
  `cert-gen`, golden captures, e2e test directory) and the dependency graph
  to support it (`@browsercore/tls`, `@browsercore/fetch`, etc.).
- Adding `browsersmith` as a *dependency* of `@browsercore/testing` closes the
  loop: the testing package can now exercise the composition root, not just
  the leaves.
- The existing `src/e2e/sink-server.ts` was designed to be reusable by any
  package — `traffic-server.ts` follows the same convention and may be
  re-exported from the package index if other packages want a known-content
  HTTPS fixture.

### 6.4 Dependency change

`package.json` gains one devDependency:

```json
"browsersmith": "0.0.3"
```

This is a **dev** dependency — the gate is a test. browsersmith's own
dependencies (the full browsercore stack) are already transitive deps of
`@browsercore/testing`, so the only new edge is the `browsersmith` root
package itself.

---

## 7. Out of Scope (v1)

- **HTTP/3 (QUIC).** The QUIC transport is opt-in and not wired into the
  default fetch path yet. Adds a separate test matrix; defer.
- **Custom CA trust store.** We use `rejectUnauthorized: false`. Testing the
  cert-verification path against a self-signed cert is a separate concern.
- **Performance benchmarking.** The gate checks correctness only. A bench on
  top (handshake RPS, throughput) is a different doc.
- **Multiple cipher suites.** Pinned to TLS_AES_128_GCM_SHA256 (chrome-140's
  preference). Parameterizing over cipher suites is v2.
- **Network error injection.** Simulating packet loss, truncation, or
  reordering requires a fault-injecting proxy. The sink-server tests cover
  some of this; the traffic gate assumes a clean local socket.

---

## 8. Acceptance Criteria

The gate is "done" when:

1. `tests/e2e/traffic-gate.test.ts` passes locally against the current
   `main` (post-Bug-6-fix) for all three matrix rows.
2. When Bug 6 is artificially reintroduced (e.g., flip one byte in the
   handshake traffic key derivation), at least one gate case fails with a
   `ProtocolError` / decryption error. This proves the gate actually catches
   the bug class it targets.
3. CI runs the gate on every PR to main and the job completes in < 30
   seconds.
4. No new files outside `src/e2e/`, `tests/e2e/`, and `docs/`.
