# captures/ — in-repo golden packet storage

Pre-recorded golden captures used by `@network/testing` for serialization and
packet-capture comparison (docs/TEST-SUITE.md, Categories 2, 3, 6, 14).

## Layout

```
captures/
  <profile>/                  # e.g. chrome-140, firefox-128
    <protocol>/               # tls | http2 | http1
      <record>.bin            # raw bytes as seen on the wire
      <record>.meta.json      # typed metadata (CaptureMeta)
```

- `<profile>` is a branded `ProfileId` (see `@network/profiles`).
- `<protocol>` is one of `tls`, `http2`, `http1`.
- `<record>` names the message: `client_hello`, `settings`, `headers`,
  `server_hello`, …

The typed manifest lives in `src/captures/manifest.ts` (it must stay under
`src/` to satisfy `rootDir`); it discovers entries from this directory.

## How to regenerate

Captures are produced with [curl-impersonate](https://github.com/lwthiker/curl-impersonate),
which impersonates a real browser's TLS + HTTP fingerprints:

```bash
# TLS ClientHello for Chrome 140 against example.com
curl-impersonate --chrome-140 -o captures/chrome-140/tls/client_hello.bin \
  --trace-ascii /dev/null https://example.com

# First HTTP/2 SETTINGS frame (capture the TLS-decrypted frames)
curl-impersonate --chrome-140 ...
```

After regenerating a `.bin`, update its sibling `.meta.json` (especially
`randomizedFields` and `createdAt`), then re-run the golden-comparison tests.

## Randomized fields

Some fields are intentionally randomized by protocol specs and CANNOT be
byte-matched. Each `.meta.json` lists them under `randomizedFields`:

| reason          | what it covers                                           |
| --------------- | -------------------------------------------------------- |
| `random`        | TLS `client_random` (32 bytes)                           |
| `ephemeral_key` | ECDHE key-share public key                               |
| `grease`        | RFC 8701 GREASE values (when randomized)                 |
| `nonce`         | Protocol nonces                                          |

The comparison helper `compareBytesWithIgnore` (in `src/utils.ts`) accepts
these ranges and masks them before comparing — this is the core mechanism
behind Category 14 (packet capture comparison). Fields NOT in this list MUST
match byte-for-byte, or the comparison fails the build.
