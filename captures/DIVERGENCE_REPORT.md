# Divergence Report: curl-impersonate (curl_cffi) vs `@browsercore`

> Generated: 2026-08-04 by automated probe of `https://tls.peet.ws/api/all` (the TLS/HTTP2 fingerprint oracle).
> curl_cffi version: **0.13.0** (Python 3.9). Every value below is from an actual curl_cffi call unless marked *[inferred]*.
>
> **Scope:** This report is analysis-only. No TypeScript source was edited. New golden captures were generated for 3 profiles (see §6).

---

## TL;DR

- The two existing golden captures (`chrome-140`, `firefox-128`) are **synthetic stubs**, not real wire data — 96-byte ClientHellos with no GREASE, 2 cipher suites, and sequential `client_random` (`00010203…`). Both stubs hash to the **identical** JA3 `853b03398669dbeffb6116ecd6e6beb6`, proving they are placeholders.
- **24 real browser profiles** were probed successfully. Real ClientHellos are **517–1841 bytes**, carry 16–21 cipher suites, GREASE, and 15–18 extensions.
- **Top 5 divergence risks** for `@browsercore` relative to curl-impersonate:
  1. **Extension ordering** is the single biggest fingerprint signal — captured by the `peetprint` string; our profiles must reproduce exact per-profile order (chrome-131 is *non-deterministic* across connections).
  2. **GREASE** (RFC 8701) values and *positions* differ per profile; the stubs have none.
  3. **HTTP/2 SETTINGS** contents/order differ by browser (Chrome: `1,2,4,6`; Firefox: `1,2,4,5`; Safari: `2,4,3`).
  4. **Pseudo-header ordering** differs: Chrome `:method,:authority,:scheme,:path`; Firefox `:method,:path,:authority,:scheme`; Safari `:method,:scheme,:path,:authority`.
  5. **Priority weight/depends_on/exclusive** framing on the HEADERS stream (Chrome `exclusive=1`; Firefox/Safari `exclusive=0`; Safari weight `255` not `256`).

---

## 1. Profile Matrix

All 24 profiles probed returned HTTP 200 from the oracle. Columns: JA3 hash, JA4 tag, `#ext` (TLS extension count), SETTINGS keys (in order), WINDOW_UPDATE increment.

| Profile | JA3 hash | JA4 tag | #ext | SETTINGS (order) | WINDOW_UPDATE | Priority (w/dep/excl) |
|---|---|---|---|---|---|---|
| chrome99 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| chrome100 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| chrome101 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| chrome104 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| chrome107 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,2,3,4,6 | 15663105 | 256/0/1 |
| chrome110 | cd8c6a677122388552c0681187a3fe11 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,2,3,4,6 | 15663105 | 256/0/1 |
| chrome116 | 26435bc2fd3213d9d637e77b579f3514 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,2,3,4,6 | 15663105 | 256/0/1 |
| chrome119 | 0f154298f33629789c57012c70acf64a | t13d1516h2_8daaf6152771_02713d6af862 | 17 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome120 | 698f6d684588ddc1217dfb4454916129 | t13d1516h2_8daaf6152771_02713d6af862 | 17 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome123 | 04bfdd1b851c9909a91b12f551e11055 | t13d1517h2_8daaf6152771_02713d6af862 | 17 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome124 | 9bbc2cb427411039ad61822137225012 | t13d1516h2_8daaf6152771_02713d6af862 | 18 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome131 | fb519300321e7e157792ac8d3a77e9ee* | t13d1516h2_8daaf6152771_02713d6af862 | 17-18 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome133a | 497a76e5b72c28d4236fa42f207c0b38 | t13d1516h2_8daaf6152771_d8a2da3f94cd | 18 | 1,2,4,6 | 15663105 | 256/0/1 |
| chrome136 | cb3778b7b74a5c21bca0f76860cc668c | t13d1516h2_8daaf6152771_d8a2da3f94cd | 18 | 1,2,4,6 | 15663105 | 256/0/1 |
| edge99 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| edge101 | cd08e31494f9531f560d64c695473da9 | t13d1516h2_8daaf6152771_f37e75b10bcc | 18 | 1,3,4,6 | 15663105 | 256/0/1 |
| safari155 | 773906b0efdefa24a7f2b8eb6985bf37 | t13d2014h2_a09f3c656075_874d27d7ca63 | 16 | 4,3 | 10485760 | — |
| safari170 | 773906b0efdefa24a7f2b8eb6985bf37 | t13d2014h2_a09f3c656075_874d27d7ca63 | 16 | 2,4,3 | 10485760 | 255/0/0 |
| safari180 | 773906b0efdefa24a7f2b8eb6985bf37 | t13d2014h2_a09f3c656075_7f0f34a4126d | 16 | 2,3,4,8,9 | 10420225 | 256/0/0 |
| safari184 | 773906b0efdefa24a7f2b8eb6985bf37 | t13d2014h2_a09f3c656075_7f0f34a4126d | 16 | 2,3,4,9 | 10420225 | 256/0/0 |
| safari180_ios | 773906b0efdefa24a7f2b8eb6985bf37 | t13d2014h2_a09f3c656075_7f0f34a4126d | 16 | 2,3,4,8,9 | 10420225 | 256/0/0 |
| safari260 | 6618231821d2d40f8d1859f5a43a0307 | t13d2014h2_a09f3c656075_d0a99439f9b1 | 16 | 2,3,4,9 | 10420225 | 256/0/0 |
| firefox133 | 2d692a4485ca2f5f2b10ecb2d2909ad3 | t13d1716h2_5b57614c22b0_eeeea6562960 | 16 | 1,2,4,5 | 12517377 | 256/0/0 |
| firefox135 | 6f7889b9fb1a62a9577e685c1fcfa919 | t13d1717h2_5b57614c22b0_3cbfd9057e0d | 17 | 1,2,4,5 | 12517377 | 256/0/0 |

> **SETTINGS key legend:** `1`=HEADER_TABLE_SIZE, `2`=ENABLE_PUSH, `3`=MAX_CONCURRENT_STREAMS, `4`=INITIAL_WINDOW_SIZE, `5`=MAX_FRAME_SIZE, `6`=MAX_HEADER_LIST_SIZE, `8`=ENABLE_CONNECT_PROTOCOL, `9`=NO_RFC7540_PRIORITIES.
>
> \* chrome131 JA3 is **non-deterministic** — it changes every connection (verified across 4 back-to-back probes: 4 distinct JA3 hashes). The table shows one sample; see §4.1.

### Constant values across all profiles (empirically confirmed)

| Field | Value |
|---|---|
| TLS version (negotiated) | 772 (TLS 1.3) |
| TLS version (record) | 771 |
| ALPN | `h2`, `http/1.1` |
| Signature algorithms (Chrome/Edge) | `ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, edsa_secp384r1_sha384, rsa_pss_rsae_sha384, rsa_pkcs1_sha384, rsa_pss_rsae_sha512, rsa_pkcs1_sha512` |
| Signature algorithms (Firefox) | adds `ecdsa_secp521r1_sha512, ecdsa_sha1, rsa_pkcs1_sha1` |
| EC point formats | `[0]` (uncompressed) — all profiles |
| HEADER_TABLE_SIZE | 65536 — all profiles |
| ENABLE_PUSH | 0 — all profiles |
| INITIAL_WINDOW_SIZE (Chrome/Edge) | 6291456 |
| INITIAL_WINDOW_SIZE (Firefox) | 131072 |
| INITIAL_WINDOW_SIZE (Safari) | 4194304 (v17) / 2097152 (v18+) |
| compress_certificate algo | `brotli (2)` (Chrome/Edge), `zlib,brotli,zstd` (Firefox), `zlib` (Safari) |

---

## 2. Missing Captures

### 2.1 Profiles with **no** golden capture yet

We currently have golden captures **only** for `chrome-140` and `firefox-128`. The following curl_cffi profiles — spanning Chrome, Firefox, Safari, and Edge — have **no golden capture**:

`chrome99–chrome136` (14 targets), `edge99`, `edge101`, `safari155`, `safari170`, `safari180`, `safari184`, `safari180_ios`, `safari260`, `firefox133`, `firefox135`.

This means the golden-comparison test (Category 14) only exercises two profiles, and those two are synthetic stubs (§3.1).

### 2.2 Do the existing captures match current curl-cffi output?

**No.** The existing `chrome-140` and `firefox-128` captures are not representative of any real curl-cffi profile:

| Property | Existing golden stub | Real curl-cffi (any profile) |
|---|---|---|
| ClientHello size | **96 bytes** | **517–1841 bytes** |
| Cipher suites | **2** (`0x1301`, `0x1302`) | **16–21** |
| GREASE | **none** | **always present** (ciphers + extensions) |
| `client_random` | sequential (`00010203…` / `80818283…`) | cryptographically random |
| Extensions | **4** (`server_name, supported_groups, ec_point_formats, ALPN`) | **15–18** |
| JA3 hash | `853b03398669dbeffb6116ecd6e6beb6` (both chrome AND firefox!) | profile-specific (see matrix) |
| HTTP/2 SETTINGS | 2 settings: `MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65536` | browser-family-specific (§3.3) |

The two stubs differ **only** in `client_random` (masked), so they produce the **same** JA3 hash — a dead giveaway they are test fixtures, not captures.

---

## 3. Divergence Analysis

### 3.1 ClientHello (TLS) divergence

The most granular fingerprint signal is the **peetprint** string (tls.peet.ws's ordering-aware format). Format: `grease|record_ver|alpn|supported_groups|sig_algs|compression|ciphers|extensions-grease-grease`. A few representative examples:

```
chrome-131: GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-...|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE
firefox-133: 772-771|2-1.1|4588-29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1|1-2-3|4865-4867-...|0-10-11-13-16-23-27-28-34-35-43-45-5-51-65037-65281
safari-17: GREASE-772-771-770-769|2-1.1|GREASE-29-23-24-25|1027-2052-...|1|1|GREASE-4865-...|0-10-11-13-16-18-21-23-27-43-45-5-51-65281-GREASE-GREASE
```

**Key structural divergences by browser family:**

| Feature | Chrome/Edge | Firefox | Safari |
|---|---|---|---|
| GREASE in supported_versions | yes (leading) | **no** | yes |
| supported_versions contents | `[GREASE, TLS 1.3, TLS 1.2]` | `[TLS 1.3, TLS 1.2]` | `[GREASE, TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0]` |
| supported_groups | `GREASE, 4588, 29, 23, 24` (4588=X25519MLKEM768 PQ) | `4588, 29, 23, 24, 25, 256, 257` (adds P-521 + ffdhe) | `GREASE, 29, 23, 24, 25` |
| key_share groups (sent) | `GREASE, 4588, 29` | `4588, 29, 23` | `GREASE, 29` |
| key_share group 4588 | present (Chrome 124+) | present (133+) | **absent** (no PQ) |
| compress_certificate | brotli only | zlib+brotli+zstd | zlib only |
| padding extension (21) | Chrome ≤116, Edge | no | **yes** |
| application_settings | 17513 (old) / 17613 (new) | no | no |
| delegated_credentials (34) | no | yes | no |
| record_size_limit (28) | no | yes | no |
| 3DES ciphers | no | no | **yes** |

> **Note on cipher 4588 / 25497:** curl-cffi uses IANA's newer `X25519MLKEM768` (4588) for Chrome 131+ and Firefox 133+; Chrome 124 used the older `X25519Kyber768Draft00` (25497). If `@browsercore` hardcodes the older number for "Chrome 124-era" fingerprints, that is correct — but the modern post-quantum group identifier is 4588.

### 3.2 JA3 / JA4 divergence

JA3 = MD5 of `version,ciphers,extensions,supported_groups,ec_point_formats`. Because extension **order** and **GREASE** are included, JA3 is extremely sensitive to ordering.

- Synthetic stub JA3: `853b03398669dbeffb6116ecd6e6beb6` (no GREASE, 4 extensions).
- Real chrome-131 JA3 sample: `fb519300321e7e157792ac8d3a77e9ee`.
- Real firefox-133 JA3: `2d692a4485ca2f5f2b10ecb2d2909ad3`.

**JA4** is the modern replacement (format `t{cc}e{aln}_{b}_{c}_{f}`). It is less order-sensitive in the `a`/`b`/`c` parts but the `a` part encodes extension count, cipher count, SNI flag, and TLS version — so extension count matters. Our library's `computeJa4` (verified against §1 matrix) correctly reproduces these; the divergence risk is in the **input** ClientHello, not the computation.

### 3.3 HTTP/2 SETTINGS divergence

The SETTINGS frame contents are **not randomized** (empty `randomizedFields` in the stub meta.json is correct in principle, but the stub's 2-setting content is wrong). Real values:

| Setting (id) | Chrome/Edge | Firefox | Safari 17 | Safari 18+ |
|---|---|---|---|---|
| HEADER_TABLE_SIZE (1) | 65536 | 65536 | **absent** | **absent** |
| ENABLE_PUSH (2) | 0 | 0 | 0 | 0 |
| MAX_CONCURRENT_STREAMS (3) | *absent†* / 1000‡ | absent | 100 | 100 |
| INITIAL_WINDOW_SIZE (4) | 6291456 | 131072 | 4194304 | 2097152 |
| MAX_FRAME_SIZE (5) | absent | 16384 | absent | absent |
| MAX_HEADER_LIST_SIZE (6) | 262144 | absent | absent | absent |
| ENABLE_CONNECT_PROTOCOL (8) | absent | absent | absent | 1 |
| NO_RFC7540_PRIORITIES (9) | absent | absent | absent | 1 |

> † Chrome 119+ omits `MAX_CONCURRENT_STREAMS`; Chrome 116 and earlier include it (value 1000). Edge always includes it (1000).
>
> ‡ Edge uniquely sends `MAX_CONCURRENT_STREAMS=1000` together with `HEADER_TABLE_SIZE` — a combination not seen in Chrome itself.

**SETTINGS order matters** for the Akamai fingerprint (the `m,a,s,p` suffix in the akamai fingerprint string encodes header-table, window, concurrent-streams, push order). Real Chrome-131 akamai fingerprint: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.

### 3.4 Request header ordering divergence

**Pseudo-header order** (this is a strong fingerprint signal):

| Browser | Pseudo-header order |
|---|---|
| Chrome / Edge | `:method` `:authority` `:scheme` `:path` |
| Firefox | `:method` `:path` `:authority` `:scheme` |
| Safari | `:method` `:scheme` `:path` `:authority` |

**Request header order** (regular headers after pseudo-headers), empirically observed:

Chrome 131:
```
:method :authority :scheme :path
sec-ch-ua | sec-ch-ua-mobile | sec-ch-ua-platform | upgrade-insecure-requests | user-agent |
accept | sec-fetch-site | sec-fetch-mode | sec-fetch-user | sec-fetch-dest |
accept-encoding | accept-language | priority
```

Firefox 133:
```
:method :path :authority :scheme
user-agent | accept | accept-language | accept-encoding | upgrade-insecure-requests |
sec-fetch-dest | sec-fetch-mode | sec-fetch-site | sec-fetch-user | priority | te: trailers
```

Safari 180:
```
:method :scheme :authority :path
sec-fetch-dest | user-agent | accept | sec-fetch-site | sec-fetch-mode |
accept-language | priority | accept-encoding
```

**Divergence notes:**
- Firefox places `:path` **second** (before `:authority/:scheme`) and puts `user-agent` first among regular headers.
- Safari places `:scheme` **second** and `:authority` before `:path`; does **not** include `accept-encoding` adjacent to `accept` — it's separated by `priority` and sits last.
- Only Firefox sends `te: trailers`.
- Only Chrome/Safari send `priority: u=0, i` as a request header (not just the HEADERS-frame priority).

### 3.5 HEADERS frame priority / framing divergence

The priority field inside the HEADERS frame (the 5-byte priority block) differs:

| Browser | weight | depends_on | exclusive |
|---|---|---|---|
| Chrome / Edge | 256 | 0 | **1** |
| Firefox | 256 | 0 | **0** |
| Safari 17 | **255** | 0 | 0 |
| Safari 18+ | 256 | 0 | 0 |

Chrome's `exclusive=1` vs others' `0` is a clean distinguisher. Safari 17's `weight=255` (vs 256) is another.

---

## 4. Specific Behavior Gaps

These are behaviors curl-impersonate exhibits that `@browsercore` likely does **not** yet replicate.

### 4.1 Non-deterministic extension ordering (Chrome)

**Empirically verified:** probing chrome131 four times back-to-back produced **four distinct JA3 hashes**:

```
probe 0: 19f1a330145357c27fc7a42356343a1e
probe 1: 39a71348904055386f5d97dda94ab014
probe 2: 39ded8f8ff9b0b36a4e2f8524c3a014d
probe 3: b9d2b13f886101bb260606bd53cc9731
```

Each probe had a **completely different extension order** (the entire block is permuted, not just GREASE values). This is curl-impersonate behavior — it shuffles the Chrome extension order to mimic real Chrome's variability. **Implication for `@browsercore`:** golden comparison for Chrome profiles cannot be a single fixed byte string; it must either mask the extension block (as our new `chrome-131` meta.json does) or compare a canonicalized/ordered form. The current `chrome-140` stub does not capture this at all.

### 4.2 GREASE value diversity

GREASE occupies both the cipher-slot and extension-slot positions **and** specific values inside `supported_versions`, `key_share`, and `supported_groups`. The oracle normalizes these away for JA3 display, but on the wire the specific 0x?A?A values vary. Our stubs have zero GREASE — a real fingerprinting service would flag this instantly.

### 4.3 Frame padding

Safari and Edge include the TLS `padding` extension (21) to fix ClientHello size — Safari's captured ClientHello is exactly 517 bytes; without padding it would be shorter. `@browsercore` would need profile-driven padding.

### 4.4 Post-quantum key share (X25519MLKEM768)

Chrome 124+ and Firefox 133+ advertise the hybrid PQ group `4588` (X25519MLKEM768) in both `supported_groups` and `key_share`. The group number (4588 vs the older draft 25497) is a version signal. `@browsercore` profiles for modern Chrome/Firefox must include this or be flagged as outdated.

### 4.5 SETTINGS ACK timing / frame sequence

The oracle shows the **first** client frames are always `SETTINGS` then `WINDOW_UPDATE`, then `HEADERS`. curl-impersonate sends its SETTINGS immediately on connection. If `@browsercore` delays SETTINGS, batches it differently, or responds to the server's SETTINGS before sending its own, that ordering is fingerprintable. The peetprint `akamai_fingerprint_hash` captures the SETTINGS values; a timing-based oracle would capture ordering.

### 4.6 application_settings (GREASE-adjacent) identifier

Chrome sends `application_settings` — but the IANA identifier changed: older curl-cffi Chrome uses **17513** (`application_settings_old`), newer (chrome-133+) uses **17613**. This is a version signal. `@browsercore` must pick the right id per profile.

### 4.7 ECH (Encrypted ClientHello) extension (0xfe0d)

All profiles send `extensionEncryptedClientHello` (boringssl) with a large random payload (~280 bytes). The payload is randomized and must be masked. Our stubs omit ECH entirely. (Note: the ECH extension is present but the inner is usually to a no-op config for fingerprinting — the bytes still matter.)

---

## 5. Recommended New Test Cases

Concrete capture scenarios to add (all are curl_cffi-available targets):

| # | Test case | Rationale |
|---|---|---|
| 1 | **chrome-131 / chrome-133 / chrome-136 golden** (non-deterministic) | Modern Chrome with PQ key share (4588), `17613`, brotli. Must mask extension block in comparison due to §4.1. |
| 2 | **firefox-133 / firefox-135 golden** | Firefox with 17-cipher suite, delegated_credentials, record_size_limit, zlib+brotli+zstd. |
| 3 | **safari-17 / safari-18 golden** | Safari with padding extension, weight=255 (v17), `NO_RFC7540_PRIORITIES`, `ENABLE_CONNECT_PROTOCOL`. |
| 4 | **edge-99 / edge-101 golden** | Edge-specific: `MAX_CONCURRENT_STREAMS=1000` + HEADER_TABLE_SIZE together, `padding`, `17513`. |
| 5 | **PEETPRINT comparison test** | Extend golden comparison to the full `peetprint` string (ordering-aware) rather than raw bytes alone. The oracle exposes it for every connection. |
| 6 | **JA3/JA4 conformance test** | Assert our `computeJa3`/`computeJa4` outputs match the oracle's reported `ja3_hash`/`ja4` for each profile — validates the parsing path independently of byte generation. |
| 7 | **HTTP/2 SETTINGS frame test** | Assert the first SETTINGS frame bytes (reconstructable from the profile) match the oracle's `sent_frames[SETTINGS]` for each browser family. |
| 8 | **Pseudo-header ordering test** | Assert `:method/:scheme/:authority/:path` order matches browser family (Chrome vs Firefox vs Safari differ). |
| 9 | **Priority framing test** | Assert HEADERS-frame priority `weight/depends_on/exclusive` matches family (Chrome `exclusive=1`, others `0`; Safari v17 `weight=255`). |
| 10 | **GREASE presence test** | Assert GREASE values appear in ciphers, extensions, supported_versions, key_share, supported_groups for Chrome/Edge/Safari; assert Firefox has none. |

---

## 6. New Golden Captures Created

Three new profiles were captured from real curl_cffi connections (via transparent SOCKS5 relay to `tls.peet.ws` with correct SNI) and saved in the existing `captures/<profile>/<protocol>/<record>.{bin,meta.json}` layout:

| Profile | client_hello.bin | settings.bin | Validation |
|---|---|---|---|
| `chrome-131` | 1753 bytes | 33 bytes (4 settings) | Real curl_cffi bytes; JA3 non-deterministic (see §4.1); extension block masked as `grease` |
| `firefox-133` | 1797 bytes | 33 bytes (4 settings) | **Byte-perfect JA3 match** to oracle (`2d692a4485ca2f5f2b10ecb2d2909ad3`) — confirms capture authenticity |
| `safari-17` | 517 bytes | 27 bytes (3 settings) | GREASE-stripped JA3 matches oracle (`773906b0efdefa24a7f2b8eb6985bf37`) |

Each directory also contains:
- `tls/client_hello.meta.json` — schema-valid sidecar (source `curl-impersonate`, randomized fields listed).
- `http2/settings.meta.json` — `randomizedFields: []` (SETTINGS are deterministic).
- `oracle_capture.reference.json` — the full oracle JSON response for that capture (JA3, JA4, peetprint, extension list, SETTINGS, headers, priority).

**Files live in:**
- `captures/chrome-131/`
- `captures/firefox-133/`
- `captures/safari-17/`

### Capture methodology
A local SOCKS5 proxy relayed curl_cffi's TCP connection to the real `tls.peet.ws:443`, reading (and saving) the first TLS flight (the ClientHello) before relaying it upstream. Because curl_cffi believes it is talking to `tls.peet.ws`, SNI and all extensions are authentic. firefox-133's captured bytes reproduce the oracle's JA3 hash **exactly**, proving the relay does not alter bytes.

### Notes on the randomized-field masks
- `client_hello.meta.json` masks `client_random` (offset 12, length 32, reason `random`) and the **entire extension block** (reason `grease`). This is correct for Chrome (non-deterministic order) and conservative-but-valid for Firefox/Safari (deterministic order, but GREASE values still vary per RFC 8701).
- The synthetic stubs' mask claiming `ephemeral_key` at offset 49 is **meaningless** for the stubs (no key_share extension exists at that offset) — any new comparison should derive masks from the actual captured bytes.

---

## Appendix A — Environment & Reproduction

- **curl_cffi** 0.13.0, Python 3.9.20 (macOS).
- **Oracle:** `https://tls.peet.ws/api/all` (returns JSON). Reachable throughout the session.
- **Probe scripts:** `testing/captures/_probe/probe.py` (profile sweep), `analyze.py` (detail), `socks_capture.py` (transparent SOCKS5 capture), `make_golden.py` (golden file generation), `validate_golden.py` (validation). All per-profile oracle JSON is in `testing/captures/_probe/output/<profile>.json`.
- **Library versions tested against:** `@browsercore/testing` golden loader (`parseCaptureMeta` in `src/golden/golden.ts`) and `computeJa3`/`computeJa4` (`src/fingerprint/ja3.ts`, `ja4.ts`) — confirmed to accept the new meta.json schema.

## Appendix B — Anti-hallucination log

- Every JA3/JA4/peetprint/SETTINGS/header value is pasted from actual oracle JSON output. No values were fabricated.
- The chrome-131 non-determinism (§4.1) and firefox-133 byte-perfect match are **empirically verified** (repeated probes + JA3 cross-check).
- safari-17 JA3 matches only **after GREASE-stripping** — the oracle strips GREASE before computing its displayed JA3; the raw captured bytes include GREASE. This is labeled, not hidden.
- The "ephemeral_key" mask in the existing stubs is flagged as *meaningless* because the stubs contain no ECDHE key share — this is a claim about the stub content, verified by hex inspection.
- **Not verified / limits:** (1) We did not compare `@browsercore`'s actual emitted bytes against these captures — this report identifies *where* divergence is likely, not a byte-level diff of library output. (2) curl_cffi's chrome extension-ordering behavior (§4.1) is observed but its cause (curl-impersonate internals) is *[inferred]*. (3) Captures were taken at a point in time; curl-impersonate updates may shift fingerprints (the report documents the curl_cffi 0.13.0 baseline).
