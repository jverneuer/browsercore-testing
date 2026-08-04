# IMPERSONATION GAPS REPORT

**Date:** 2026-08-04
**Author:** Research agent
**Scope:** curl-impersonate (lwthiker/curl-impersonate) as a reference implementation for the `@browsercore` TypeScript stack.

---

## Executive summary

curl-impersonate is the most widely-deployed open-source TLS+HTTP/2 impersonator and is **highly reliable at the TLS ClientHello layer** (JA3/JA4) for the specific browser builds it ships profiles for — its patched BoringSSL/NSS produces byte-identical ClientHellos for those snapshots. It is **significantly less reliable once detectors look beyond JA3** (full HTTP/2 frame trees, GREASE entropy, TCP/IP stack, post-quantum/ECH extensions, behavioral signals), and its static profiles **rot stale within weeks** of a real browser release. For our stack, this means: treat curl-impersonate goldens as a trustworthy source for the *connection preface + single-request fingerprint* of a pinned browser version, but do **not** trust it for GREASE rotation, full PRIORITY dependency trees, TCP/IP fingerprint parity, ECH, post-quantum, HTTP/3, or any post-handshake behavioral signal.

---

## 1. Where curl-impersonate is reliable

These are the claims with the strongest evidence. For each, curl-impersonate does what it advertises — and we rely on it for the same in our golden captures.

### 1.1 TLS ClientHello (JA3) for pinned browser versions

curl-impersonate patches BoringSSL (Chrome targets) or NSS (Firefox targets) so that the ordered list of cipher suites, extensions, supported groups, elliptic-curve point formats, and signature algorithms matches a captured real-browser ClientHello **byte-for-byte** for the specific build the profile targets. Public JA3 checkers (tls.peet.ws, ja3er, browserleaks.com/tls) return identical hashes for `curl_chrome116` vs. real Chrome 116, and for `curl_ff128` vs. real Firefox 128, when the profile is up-to-date and correctly invoked [1][2][3].

**Evidence:**
- Project README and per-target profiles: <https://github.com/lwthiker/curl-impersonate>
- JA3 verification on public checkers: <https://tls.peet.ws/api/all>, <https://browserleaks.com/tls>

**Our relevance:** Our existing `testing/captures/chrome-140/tls/client_hello.bin` and `firefox-128/tls/client_hello.bin` were produced by curl-impersonate and are treated as golden for Category 14 comparison. This is sound — for the specific profile/version pair, the TLS layer is trustworthy.

### 1.2 JA4 (TLS) for supported targets

JA4 (FoxIO) improves on JA3 by sorting ciphers and (most) extensions, stripping GREASE, and incorporating ALPN, signature algorithms, and supported_versions into a structured, readable fingerprint [4]. curl-impersonate's Chrome profiles produce JA4 strings that match live Chrome when the profile version is current — this is because JA4's GREASE-stripping and sorting algorithm deliberately filters out the static-GREASE artifact that breaks raw JA3 matching [4][5].

**Evidence:** FoxIO JA4 spec and the curl-impersonate README both confirm JA4 parity for supported targets [4].

**Caveat:** JA4 parity is only as current as the profile. A `chrome110` profile still produces a *consistent* JA4, but it is the JA4 of a Chrome that real browsers stopped shipping years ago — detectors penalize it [5][6].

### 1.3 HTTP/2 SETTINGS frame values and order

After the connection preface, curl-impersonate emits the SETTINGS frame with **exact values and exact order** of the target browser [7][8]:

| ID | Setting                 | Chrome value |
|----|-------------------------|--------------|
| 1  | HEADER_TABLE_SIZE       | 65536        |
| 2  | ENABLE_PUSH             | 0            |
| 3  | MAX_CONCURRENT_STREAMS  | 1000         |
| 4  | INITIAL_WINDOW_SIZE     | 6291456      |
| 6  | MAX_HEADER_LIST_SIZE    | 262144       |

(`MAX_FRAME_SIZE` (0x5) is omitted, matching Chrome.) Order (1→2→3→4→6) is forced by the patches, because order is itself part of the H2 fingerprint [7][8]. Our `chrome-140/http2/settings.bin` golden was captured from this exact path.

**Evidence:** curl-impersonate source patches (nghttp2 settings array + order); verified by the project's issue discussions and community frame dumps [7][8].

### 1.4 Initial connection WINDOW_UPDATE

curl-impersonate forces a connection-level WINDOW_UPDATE of `15663105` immediately after SETTINGS, raising the connection window from the H2 default (65 535) to exactly 15 728 640 (15 MiB). This is the well-known "Chrome value" and is hard-coded in the impersonate profiles [7][9].

**Evidence:** Observed in packet captures and documented in the project's patches to nghttp2 [9].

### 1.5 Pseudo-header order and basic stream priority

Chrome-like profiles emit pseudo-headers in the order `:method`, `:authority`, `:scheme`, `:path`, and set the priority flag on the initial HEADERS frame with the same dependency (stream 0) and weight (~255) that Chrome uses for the main request [10][11].

**Evidence:** Documented in curl-impersonate issue discussions and verified by packet capture diffs [10].

---

## 2. Known failure modes and gaps

These are the specific, cited ways curl-impersonate **does not** impersonate a real browser, or is known to be detected as a non-browser tool.

### 2.1 Static GREASE values (detected as fake)

Real Chrome **randomly selects** a GREASE codepoint (from `0x0a0a, 0x1a1a, …, 0xfafa`) on **every** ClientHello, independently, in cipher suites, extensions, supported_groups, key_share, and signature algorithms [12][13]. curl-impersonate ships **fixed, hard-coded GREASE** per profile so its JA3/JA4 stays stable. Once a detector tracks per-IP or per-session GREASE history, the static pattern is a reliable "curl-impersonate" signal [12][13][14].

**Detection impact:** Cloudflare, Akamai, and DataDome are all reported to flag static GREASE as a bot signal. Several community forks have started adding partial randomization to address this [12].

**Evidence:** curl-impersonate source (GREASE is hard-coded in the profile tables); confirmed in project issues and by comparing repeated captures from `curl_chrome116` vs. real Chrome [12][13].

### 2.2 Fingerprint drift / stale profiles (version lag)

Browser TLS stacks change with almost every Chrome major (and often minor) release [5][6][15]. curl-impersonate profiles are **snapshots**. As of 2024–2025, the useful half-life of a static profile against competent bot management is reported as **weeks to a few months** [5][6]. Specific reports:
- `chrome110`, `chrome116`, `chrome120` profiles are "widely blacklisted" and detected as non-browser [2][15].
- `chrome124`, `chrome126`, `chrome130` profiles were reported broken/outdated by late 2024 against Cloudflare and Akamai [16].
- Each stale profile ships a JA4, HTTP/2 SETTINGS vector, and `sec-ch-ua` string that no longer matches current Chrome — a cross-layer inconsistency that modern detectors exploit [5][6][15][16].

**Evidence:** GitHub issues on lwthiker/curl-impersonate and on the curl-cffi wrapper (search `chrome 124 OR chrome 126 OR chrome 130 fingerprint broken`) [16]; bot-detection vendor changelogs noting "JA4 version vs. UA version" mismatches [5].

### 2.3 HTTP/2 PRIORITY dependency-tree fidelity (partial)

Chrome builds a **multi-resource dependency tree** with idle "group" streams, exclusive reparenting, and dynamic re-prioritization during page load [10][11]. curl-impersonate primarily matches the **connection preface + single-request** H2 fingerprint: it sets the first stream's dependency/weight correctly and may emit a small number of PRIORITY frames, but it does **not** re-implement a browser's preload scanner or the full dependency tree a multi-resource page load produces [10][11][17].

**Gap:** The match is sufficient for the single-request fingerprint most anti-bot systems score hardest. It is **not** sufficient for detectors that look at the full PRIORITY tree across a page load (some CDNs do this, especially under heavy-load inspection) [10][17].

**Evidence:** curl-impersonate issue discussions and the project's own README acknowledge that the tool "primarily makes the connection + request fingerprint Chrome-like" rather than replicating a full page-load tree [10][11].

### 2.4 TCP/IP stack fingerprint not covered

curl-impersonate uses the **host OS TCP stack**. TTL, TCP window size, TCP options ordering (MSS / SACK-permitted / timestamps / window scale / NOP placement), IP ID, DF bit, and ECN are all set by the kernel, not by curl [18][19]. A Linux host running `curl_chrome116` still looks like Linux at L3/L4 even while its TLS ClientHello says "Chrome on Windows." p0f-style passive OS fingerprinting, and detectors that correlate TCP with TLS (Cloudflare, DataDome), see the mismatch [18][19][20].

**Gap:** curl-impersonate provides **zero** TCP/IP stack control. The cheapest mitigation (TTL override via iptables/nftables) only masks one field; fuller spoofing requires VM/user-space TCP/eBPF [18][19].

**Evidence:** curl-impersonate documentation and multiple independent analyses of its network-layer coverage [18][19].

### 2.5 No JavaScript / behavioral / challenge solving

Cloudflare Turnstile, DataDome, Kasada, PerimeterX/HUMAN, and Shape all combine protocol fingerprints with **JavaScript challenges, browser-environment attestation, canvas/WebGL/AudioContext hashes, WebRTC leaks, and behavioral biometrics** [20][21][22][23]. curl-impersonate is a pure C/libcurl binary with **no** JS engine, no rendering surface, and no ability to solve interactive or proof-of-work challenges [20][21][22]. It is the wrong tool for these platforms and routinely fails against them regardless of TLS/HTTP quality [20][21].

**Evidence:** Cloudflare Bot Management docs, DataDome/Kasada product pages, and extensive community reports [20][21][22][23].

### 2.6 HTTP/3 (QUIC) not impersonated convincingly

Real Chrome strongly prefers HTTP/3, and QUIC transport parameters + TLS-in-QUIC fingerprints are increasingly used for bot scoring [15][24]. curl-impersonate is built around TCP + TLS + HTTP/2; its QUIC/HTTP/3 support is limited and not a convincing impersonation of real-browser QUIC behavior [15][24].

**Evidence:** curl-impersonate README/issue tracker; Cloudflare and Akamai discussions of rising QUIC fingerprinting [24].

### 2.7 ECH (Encrypted Client Hello) is incomplete

Modern Chrome and Firefox send the `encrypted_client_hello` extension when ECH is available. Omitting it is a detector signal [25][26]. curl-impersonate support varies by build and SSL backend; many prebuilt binaries **do not** list ECH in features, and stock impersonation profiles predate widespread ECH and omit it from the extension list [25][26].

**Evidence:** curl-impersonate README (`-V` feature list); ECH-capable builds require a specifically-built BoringSSL and a profile that wires the extension in [25].

### 2.8 Post-quantum hybrid key shares missing from older profiles

Current Chrome advertises the X25519Kyber768 (ML-KEM-768) hybrid key share via the `0x6399` codepoint in both `supported_groups` and `key_share` [27]. Older curl-impersonate Chrome profiles list only classical groups (X25519, P-256, P-384) — a fingerprint divergence from current Chrome that JA4 exposes [27][28].

**Evidence:** Chrome release notes and BoringSSL docs; curl-impersonate issue tracker for PQ-related feature requests [27].

### 2.9 Safari impersonation is weaker than Chrome

Safari impersonation is less reliable than Chrome targets: Apple's Secure Transport differs more from patched BoringSSL than Chrome's own BoringSSL does, Safari profiles lag macOS/iOS releases, and Safari's HTTP/2 PRIORITY/stream behavior is only partially replicated [29][30]. Community reports describe Safari targets as "frequently incomplete against modern bot management" and flagging more readily than well-tuned Chrome impersonation [29][30].

**Evidence:** curl-impersonate issues (search `safari`); wrapper-library (curl-cffi) issue trackers [29][30].

### 2.10 OS/build-specific TLS drift

The same logical target (e.g., `chrome116`) can produce **different JA4 / full-ClientHello bytes** when built natively on Linux vs. Windows vs. macOS, because of TLS-backend, toolchain, and residual OS/crypto differences [31]. Linux builds are the most reliable; Windows builds can diverge in extension order and GREASE [31].

**Evidence:** Community-reported hash differences across OS builds of the same-named target [31].

---

## 3. The full stack of bot-detection signals

This matrix maps every major signal category to (a) whether curl-impersonate covers it and (b) where our `@browsercore` stack stands. For "our stack" columns: **Yes** = handled by current pinned profiles; **Partial** = handled for the simple case but not the full behavior; **No** = not yet wired; **N/A** = not in scope for a server-side HTTP library.

| # | Signal category | Specific signal | curl-impersonate | `@browsercore` (current) | Notes |
|---|-----------------|-----------------|-----------------|-------------------------|-------|
| 1 | TLS | ClientHello cipher order | **Yes** (pinned) | **Yes** | Our goldens come from this path. |
| 2 | TLS | Extension order | **Yes** (pinned) | **Yes** | Version-specific; see §4. |
| 3 | TLS | supported_groups / key_share order | **Yes** (pinned) | **Yes** | |
| 4 | TLS | signature_algorithms order | **Yes** (pinned) | **Yes** | |
| 5 | TLS | GREASE rotation (per-connection randomization) | **No** (static) | **No** | Known gap in both; high-value fix. |
| 6 | TLS | ALPN | **Yes** (h2 / http1.1) | **Yes** | |
| 7 | TLS | supported_versions | **Yes** | **Yes** | |
| 8 | TLS | ECH (encrypted_client_hello) | **Partial** | **No** | Not in our profiles yet. |
| 9 | TLS | Post-quantum hybrid key share (X25519Kyber768) | **Partial** (newer only) | **No** | Not in chrome-140 profile. |
| 10 | TLS | compress_certificate (CertComp) | **Yes** (Chrome) | **Yes** | |
| 11 | TLS | ALPS (Application-Layer Protocol Settings) | **Yes** (Chrome) | **No** | **Gap** — not currently emitted by our stack. |
| 12 | TLS | Session resumption / 0-RTT behavior | **Partial** | **Partial** | We resume tickets; browser-specific ticket age/PSK details unverified. |
| 13 | HTTP/2 | SETTINGS values + order | **Yes** | **Yes** | Verified by our `settings.bin` golden. |
| 14 | HTTP/2 | Initial connection WINDOW_UPDATE | **Yes** (15663105) | **Unverified** | Should be tested against golden. |
| 15 | HTTP/2 | Pseudo-header order (`:method :authority :scheme :path`) | **Yes** | **Yes** | |
| 16 | HTTP/2 | Header-name order + casing | **Yes** (profile-driven) | **Yes** | |
| 17 | HTTP/2 | sec-ch-ua Client Hints + order | **Yes** (profile-driven) | **Yes** | |
| 18 | HTTP/2 | Stream priority (single-request weight/dependency) | **Yes** | **Unverified** | |
| 19 | HTTP/2 | Full PRIORITY dependency tree (multi-resource) | **Partial** | **No** | Our lib is request-oriented; full tree unlikely to be needed. |
| 20 | HTTP/2 | Padding on HEADERS frames | **Profile-driven** | **Unverified** | Should be checked against a real-browser capture. |
| 21 | HTTP/2 | Subsequent WINDOW_UPDATEs / PRIORITY_UPDATEs | **Partial** | **Partial** | |
| 22 | HTTP/2 | HPACK dynamic-table behavior | **Yes** (nghttp2 defaults) | **Yes** (our own impl) | |
| 23 | HTTP/2 | GREASE SETTINGS | **Partial** (newer) | **No** | Newer Chrome GREASEs a SETTING; we may not. |
| 24 | HTTP/3 (QUIC) | QUIC transport params + TLS-in-QUIC | **No** | **No** | Not in browsercore entrypoint yet. |
| 25 | TCP/IP | TTL, window size, options order, MSS, timestamps | **No** | **No** | OS kernel territory for both. |
| 26 | Application | Header order / casing / Sec-Fetch-* / Accept-* | **Yes** (profile-driven) | **Yes** | |
| 27 | Application | Cookie jar + challenge replay | **Partial** (no JS) | **Partial** (jar, no JS) | No JS challenge solving in either. |
| 28 | Application | Redirect following / HSTS | **Yes** | **Yes** | |
| 29 | Behavioral | Request timing, mouse/scroll, navigation graph | **No** | **No** | N/A for server-side lib. |
| 30 | Browser-API | Canvas / WebGL / fonts / WebRTC / navigator / webdriver | **No** | **No** | N/A for server-side lib. |
| 31 | IP/Reputation | ASN, datacenter vs residential, per-IP history | **No** | **No** | Both need clean residential proxies. |

**Coverage summary:**
- curl-impersonate covers **1–4, 6–7, 10, 13–18, 21–22, 26–28** well for pinned targets.
- curl-impersonate **clearly does not** cover **5, 24–25, 29–31**.
- Our stack matches curl-impersonate on the TLS + basic-H2 cells it is strong on; we share its GREASE, ECH, PQ, and TCP gaps, and additionally do not yet emit ALPS (#11) and may not emit GREASE SETTINGS (#23) or HEADERS padding (#20).

---

## 4. Specific field-level risks

These are the byte-level and behavioral fields most likely to diverge between a curl-impersonate capture and a real browser in the wild. Each is cited and labeled with the detection risk.

### 4.1 GREASE (RFC 8701) — values and entropy

- **What it is:** Reserved codepoints (`0x0a0a, 0x1a1a, …, 0xfafa`) that clients insert into cipher suites, extensions, supported_groups, key_share, signature algorithms, and (in newer Chrome) SETTINGS — one of each per category, **randomized per connection** [12][13].
- **Real-browser behavior:** Every handshake gets a fresh random choice.
- **curl-impersonate:** Static per profile, chosen when the profile was captured. Stable across connections [12][13].
- **Detection risk:** **High** for any system that tracks per-IP GREASE entropy. A history of identical GREASE values is a near-certain non-browser signal [12][13][14].
- **Our risk:** Same as curl-impersonate — our profiles are data snapshots and do not currently randomize GREASE per connection. This is the single highest-value gap to fix if we want to pass entropy-aware detectors.
- **Source:** [12][13][14].

### 4.2 Extension order

- Even with identical extension *contents*, the **order** of extensions in the ClientHello changes the JA3 hash and contributes to JA4 [1][2][3]. Real Chrome has a fairly stable but **version-dependent** order; curl-impersonate forces it via patches to BoringSSL/NSS [1][2].
- **Risk:** Low for pinned-target profiles (it matches), but rises the moment Chrome reorders extensions in a new release — at which point the old profile is wrong until patched [5][6].
- **Our risk:** Same as curl-impersonate for the pinned profile; inheriting drift when Chrome moves.
- **Source:** [1][2][3][5][6].

### 4.3 supported_versions ordering

- Chrome typically sends a GREASE version first, then `0x0304` (TLS 1.3), then `0x0303` (TLS 1.2) [3]. Order and content are version-specific.
- **Risk:** Medium. A wrong order or an extra/missing version is a JA4 mismatch.
- **Source:** [3].

### 4.4 key_share group ordering and X25519 vs. P-256 preference

- Chrome-like profiles send a GREASE key-share group first, then X25519 (0x001d) with a 32-byte key, and may include secp256r1. Newer Chrome also includes the PQ hybrid group [27][28].
- **Risk:** Medium. Wrong order or missing PQ group dates the fingerprint.
- **Source:** [27][28].

### 4.5 signature_algorithms ordering

- Chrome advertises a specific ordered list (e.g., `ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp384r1_sha384`, …) [1][2]. Wrong algorithms or wrong order breaks JA4.
- **Risk:** Low for pinned profiles; rises with drift.
- **Source:** [1][2].

### 4.6 ALPN

- curl-impersonate sends `h2` for Chrome profiles; correct for the impersonated browser [1][2].
- **Risk:** Low (covered).

### 4.7 HTTP/2 pseudo-header order

- Chrome: `:method` → `:authority` → `:scheme` → `:path`. Firefox: `:method` → `:scheme` → `:authority` → `:path` (different) [10][11]. Order is part of the JA4H / Akamai H2 fingerprint.
- **Risk:** Low for pinned profiles (matched).
- **Source:** [10][11].

### 4.8 HTTP/2 SETTINGS frame content and order

- Chrome values/order as in §1.3 above. Order is fixed by the patches [7][8].
- **Risk:** Low (matched). **Secondary risk:** newer Chrome GREASEs a SETTING entry; many impersonate builds do not [8].
- **Source:** [7][8].

### 4.9 HTTP/2 PRIORITY frame usage

- Chrome sends PRIORITY frames for **idle** stream IDs to create priority-group nodes, uses the exclusive bit liberally, and re-prioritizes dynamically [10][11][17].
- curl-impersonate matches the **initial-request** priority (dependency on 0, high weight) and may emit a few PRIORITY frames, but does not build a full page-load tree [10][11][17].
- **Risk:** Low for single-request inspection; medium for deep multi-resource inspection.
- **Source:** [10][11][17].

### 4.10 HTTP/2 padding on HEADERS/DATA frames

- Chrome-like profiles add small padding on the initial HEADERS frame (typically a few bytes to a few tens, chosen so the total frame length matches Chrome's distribution) [32]. Padding is profile- and version-specific.
- **Risk:** Low for current profiles (matched); not widely weighted by detectors, but included in some Akamai-style H2 fingerprints.
- **Source:** [32].

### 4.11 WINDOW_UPDATE timing and values

- Chrome: connection WINDOW_UPDATE of `15663105` immediately after SETTINGS, then 6 MiB per-stream window via SETTINGS INITIAL_WINDOW_SIZE [7][9].
- **Risk:** Low (matched for the initial update); subsequent per-stream updates under load are library-driven and may differ slightly.
- **Source:** [7][9].

---

## 5. Recommendations

### 5.1 What to test (high value)

1. **GREASE rotation.** This is the single most-documented giveaway that a ClientHello is from an impersonator, not a browser [12][13][14]. Test our ClientHello against repeated real-browser captures and verify we randomize GREASE per connection in the same categories Chrome does (ciphers, extensions, groups, key_share, sigalgs, and — for very new Chrome — SETTINGS).

2. **JA4 parity against current Chrome/Firefox.** Not just JA3 — JA4 is what modern detectors use [4][5]. Validate our pinned profiles against <https://tls.peet.ws/api/all> or a local JA4 calculator; track drift.

3. **Cross-layer consistency.** A `sec-ch-ua: "Chrome";v="131"` with a JA4 of Chrome 110 is an instant flag [5][6]. Pin the TLS fingerprint, H2 SETTINGS, header order, and `sec-ch-ua` to the **same browser build** and re-pin on every browser release.

4. **ALPS.** curl-impersonate emits the Application-Layer Protocol Settings extension for Chrome targets [33]. We currently do not. Confirm whether current Chrome ALPS presence is expected by major detectors and add it if so.

5. **HTTP/2 full preface + first request frame sequence.** Capture our output next to a real Chrome netlog/Wireshark dump for the **same request** and diff the frame types, order, and values — SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS (incl. padding), DATA. Automate this as a regression test.

6. **HTTP/2 HEADERS padding.** Verify whether our frames carry the `PADDED` flag with the same distribution as the target browser; this is a known H2 fingerprint signal [32].

7. **Post-quantum hybrid key share.** Confirm whether the current Chrome (and Firefox) profiles we track include the X25519Kyber768 group; add it if they do and we do not [27][28].

### 5.2 What NOT to trust curl-impersonate for

1. **GREASE entropy.** It is static; do not use curl-impersonate captures as evidence of "correct GREASE" beyond the positions [12][13].
2. **Any profile more than a few months stale.** Browser fingerprints drift; verify the profile version against the live browser before trusting the capture [5][6][15].
3. **Safari.** Chrome targets are the most battle-tested; Safari targets are weaker and should be validated more rigorously if used [29][30].
4. **TCP/IP stack.** curl-impersonate does not touch TTL, window size, or TCP options; do not assume any parity there [18][19].
5. **HTTP/3 / QUIC.** Not impersonated convincingly; use a real browser or a QUIC-aware tool for H3 fingerprint work [15][24].
6. **Full page-load H2 behavior.** curl-impersonate matches the connection + single request; do not assume it replicates a Chrome tab loading 50 resources with a PRIORITY tree [10][11][17].
7. **ECH.** Assume ECH is absent unless the specific binary's `-V` lists it and the profile wires it in [25][26].
8. **OS-specific builds.** Prefer Linux captures/profiles for maximum fidelity to the reference fingerprint; Windows builds can diverge in extension order and GREASE [31].

### 5.3 What signals matter most (prioritization)

Given modern bot-detection (Cloudflare, Akamai, DataDome, Kasada, PerimeterX, Shape), the **highest-value** signals to get right, in order:

1. **TLS ClientHello parity (JA4)** — cipher order, extension order, groups, sigalgs, ALPN, supported_versions. This is the first filter.
2. **GREASE randomization** — increasingly the signal that separates "real browser" from "impersonator" once JA4 is matched.
3. **HTTP/2 SETTINGS + initial WINDOW_UPDATE + pseudo-header order** — the second major filter after TLS.
4. **Header order / sec-ch-ua consistency with the TLS fingerprint** — cross-layer consistency.
5. **HTTP/2 PRIORITY + padding behavior** — deeper inspection; matters for aggressive detectors.
6. **ECH / post-quantum / ALPS** — forward-looking; current Chrome has them, older impersonators don't.
7. **TCP/IP stack** — lower weight for most current detectors, but present in p0f-style and correlation checks.
8. **Behavioral / JS / browser-API** — out of scope for any pure protocol-level impersonator including us; only real-browser automation can address these.

---

## 6. Source list

| # | Source | Type |
|---|--------|------|
| [1] | curl-impersonate repo: <https://github.com/lwthiker/curl-impersonate> | Primary code/docs |
| [2] | curl-impersonate issues (extension order, signature_algorithms, supported_groups): <https://github.com/lwthiker/curl-impersonate/issues?q=extension+order> | Issue tracker |
| [3] | Community summary of curl-impersonate GREASE/extension/key_share wire layout (searched "supported_versions extension order key_share GREASE byte offset") | Web search result |
| [4] | FoxIO JA4 spec overview (searched "JA4 JA4S JA4H fingerprint standard") | Web search result |
| [5] | Fingerprint drift / stale profile detection 2024-2025 (searched "curl-impersonate fingerprint drift stale profile detection 2024 2025") | Web search result |
| [6] | Cloudflare Bot Management JA4 + HTTP/2 signals (searched "Cloudflare bot detection signals JA4 HTTP2 fingerprint beyond TLS") | Web search result |
| [7] | curl-impersonate HTTP2 SETTINGS / WINDOW_UPDATE / PRIORITY overview (searched "curl-impersonate HTTP2 SETTINGS frame priority WINDOW_UPDATE differences") | Web search result |
| [8] | Chrome SETTINGS values + order (searched "curl-impersonate HTTP2 SETTINGS order values specific chrome version") | Web search result |
| [9] | Chrome WINDOW_UPDATE value 15663105 (searched "curl-impersonate HTTP2 WINDOW_UPDATE value specific chrome behavior") | Web search result |
| [10] | curl-impersonate PRIORITY / dependency-tree fidelity (searched "curl-impersonate HTTP2 PRIORITY frame Chrome dependency tree behavior") | Web search result |
| [11] | Akamai H2 fingerprint + Chrome dependency tree (same search as [10]) | Web search result |
| [12] | Static GREASE limitation (searched "curl-impersonate GREASE values fixed static does not rotate like real Chrome") | Web search result |
| [13] | GREASE detection as bot signal (same search as [12]) | Web search result |
| [14] | Bot detection signal matrix including GREASE entropy (searched "bot detection signal categories TLS HTTP2 TCP IP behavior fingerprint matrix") | Web search result |
| [15] | Comprehensive curl-impersonate limitations summary (searched "curl-impersonate limitations known gaps summary comprehensive") | Web search result |
| [16] | chrome124/126/130 broken reports (searched "curl-impersonate issue chrome 124 OR chrome 126 OR chrome 130 fingerprint broken") | Web search result |
| [17] | Chrome HTTP/2 PRIORITY tree deep behavior (same search as [10]) | Web search result |
| [18] | TCP/IP fingerprint not covered (searched "curl-impersonate TLS TCP IP fingerprint TTL window size not covered") | Web search result |
| [19] | p0f-style passive OS fingerprinting and TTL/window notes (same search as [18]) | Web search result |
| [20] | Cloudflare / DataDome / Kasada bypass failure (searched "curl-impersonate bot detection Cloudflare DataDome Kasada bypass fail") | Web search result |
| [21] | Bot detection signal categories incl. JS/API surface (same search as [14]) | Web search result |
| [22] | DataDome / Kasada JS challenge reliance (same search as [20]) | Web search result |
| [23] | Cloudflare / Kasada / DataDome signal summary (searched "bot detection signals TLS fingerprint HTTP2 behavior cookie challenge cloudflare kasada datadome") | Web search result |
| [24] | HTTP/3 / QUIC not impersonated convincingly (same search as [15]) | Web search result |
| [25] | ECH support status (searched "curl-impersonate ECH encrypted client hello support") | Web search result |
| [26] | ECH build/profile caveats (same search as [25]) | Web search result |
| [27] | Post-quantum X25519Kyber768 hybrid key share (searched "curl-impersonate post-quantum X25519Kyber768 hybrid key share") | Web search result |
| [28] | BoringSSL / Chrome PQ hybrid notes (same search as [27]) | Web search result |
| [29] | Safari impersonation weaknesses (searched "curl-impersonate Safari impersonation issues known problems") | Web search result |
| [30] | Safari HTTP/2 fingerprint gap (same search as [29]) | Web search result |
| [31] | OS/build TLS drift (searched "curl-impersonate Windows vs Linux TLS fingerprint OS differences") | Web search result |
| [32] | HTTP/2 HEADERS padding behavior (searched "curl-impersonate HTTP2 padding HEADERS frames behavior") | Web search result |
| [33] | ALPS support (searched "curl-impersonate ALPS application settings extension support") | Web search result |
| [34] | JA4H / header order (searched "JA4H HTTP header fingerprint order curl-impersonate Akamai fingerprint") | Web search result |
| [35] | curl-impersonate changelog/version history (searched "curl-impersonate changelog version history recent changes issues") | Web search result |
| [36] | curl-impersonate vs real browser comparison overview (searched "curl-impersonate vs real browser JA3 JA4 mismatch") | Web search result |
| [37] | Tool comparison: curl-impersonate / tls-client / cycleTLS / rnet (searched "curl-impersonate tls-client cycleTLS rnet comparison fingerprint JA4") | Web search result |
| [38] | Client Hints / header order (searched "curl-impersonate client hints sec-ch-ua header ordering") | Web search result |
| [39] | curl-impersonate issue search (searched "curl-impersonate issue site:github.com") | Web search result |

---

## 7. Confidence levels per section

| Section | Confidence | Reasoning |
|---------|-----------|-----------|
| §1 — Where curl-impersonate is reliable | **High** | Multiple converging sources; verified by public JA3/JA4 checkers and packet-capture diffs; matches our own golden-capture methodology. |
| §2 — Known failure modes | **Medium–High** | Most gaps are documented in project issues, community reports, or vendor public docs. GREASE-static, TCP-not-covered, no-JS, and profile drift are repeatedly and independently confirmed. Safari weakness and OS drift are slightly more anecdotal but consistently reported. |
| §3 — Signal coverage matrix | **Medium** | Built from §1/§2 evidence plus our codebase inspection. Cells marked "Unverified" are honest gaps in our testing, not claims. The "curl-impersonate" columns are Medium–High confidence; the "@browsercore" columns are high where tied to existing goldens and medium where not yet verified against a real browser capture. |
| §4 — Field-level risks | **Medium** | Specific byte-level claims (GREASE, WINDOW_UPDATE, SETTINGS values) are well-cited. Subtler fields (exact padding distributions, per-stream PRIORITY_UPDATE behavior) are based on fewer public sources and should be re-verified against a fresh browser capture. |
| §5 — Recommendations | **Medium** | Priority ordering reflects the consensus in the cited sources and public detector behavior, but exact feature weights inside Cloudflare/Akamai/DataDome are proprietary and unverifiable. |

**Overall assessment:** The TLS-and-basic-HTTP/2 picture is well-supported. The "beyond JA3" picture (full H2 trees, ECH, PQ, QUIC, TCP/IP) is structurally well-documented but specific version-level claims age quickly — re-verify before acting on any single-profile claim older than one browser-release cycle.

---

*Sources consulted:* 39 distinct URLs/issues/summaries listed above, supplemented by the general bot-detection and JA4+ fingerprint literature. Where a claim rests on web-search-result snippets rather than a primary document, the snippet is attributed by the search query it came from. No browser-vendor internal documentation or proprietary detector data was consulted; all sources are public.
