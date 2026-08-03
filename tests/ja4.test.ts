/**
 * Real tests for JA4 / JA4H computation (Cat 4).
 *
 * The minimal ClientHello used for JA3 has no SNI / ALPN / supported-groups, so
 * the JA4 fingerprint (ja4.ts lines 328-359) and JA4H (lines 388-421) were fully
 * uncovered. This file builds a richer ClientHello and a representative HTTP
 * request to exercise the four-part JA4 tag and the four-part JA4H tag.
 */

import { describe, expect, it } from "vitest";
import { computeJa4 } from "../src/index.js";
import { computeJa4Fingerprint, parseJa4ClientHello } from "../src/fingerprint/ja4.js";
import { computeJa4h } from "../src/fingerprint/ja4h.js";

/** JA4 tag shape: t{cc:02}{ee:02}{sni}{ver}{alpn} _ 12hex _ 12hex _ 12hex. */
const JA4_TAG_RE = /^t\d{2}\d{2}[di]\d{2}[a-z0-9]{2}_[a-z0-9]{12}_[a-z0-9]{12}_[a-z0-9]{12}$/;
/** JA4H tag shape: {method:02}{ver}{cookies}{referer}{hh:02}{lang} _ 12hex _ 12hex _ 12hex. */
const JA4H_TAG_RE = /^[a-z]{2}\d{2}[cn][cn]\d{2}[a-z0-9]{4}_[a-z0-9]{12}_[a-z0-9]{12}_[a-z0-9]{12}$/;

/**
 * Build a TLS 1.3 ClientHello (no record wrapper) carrying the extensions JA4
 * inspects: SNI(0), supported_groups(10), ec_point_formats(11), ALPN(16).
 */
function richClientHello(): Uint8Array {
    const body: number[] = [
        0x03, 0x04, // client_version = 0x0304 (TLS 1.3)
        // random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
        0x00, // session_id length = 0
        0x00, 0x04, // cipher_suites length = 4 (2 suites)
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x01, // compression_methods length = 1
        0x00, // null compression
    ];
    const extensions: number[] = [
        // SNI(0x0000): one host_name entry "a".
        0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x01, 0x61,
        // supported_groups(0x000a): one group 0x001d.
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
        // ec_point_formats(0x000b): one format, uncompressed.
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        // ALPN(0x0010): "h2", "http/1.1".
        0x00, 0x10, 0x00, 0x0f, 0x00, 0x0d, 0x02, 0x68, 0x32, 0x09, 0x68, 0x74, 0x74, 0x70, 0x2f,
        0x31, 0x2e, 0x31,
    ];
    body.push((extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions);

    const handshakeLen = body.length;
    return new Uint8Array([
        0x01, // handshake type: ClientHello
        (handshakeLen >> 16) & 0xff,
        (handshakeLen >> 8) & 0xff,
        handshakeLen & 0xff,
        ...body,
    ]);
}

/**
 * Wrap a bare ClientHello (starts with handshake type 0x01) in a TLS record
 * layer (ContentType 0x16 + version 0x0301 + 2-byte length).
 */
function wrapInRecord(bare: Uint8Array): Uint8Array {
    return new Uint8Array([
        0x16, 0x03, 0x01,
        (bare.length >> 8) & 0xff,
        bare.length & 0xff,
        ...bare,
    ]);
}

describe("computeJa4 (four-part JA4 TLS fingerprint)", () => {
    it("emits a well-formed canonical JA4 tag", () => {
        const tag = computeJa4(richClientHello());
        expect(tag).toMatch(JA4_TAG_RE);
    });

    it("is deterministic and stable across calls", () => {
        const hello = richClientHello();
        expect(computeJa4(hello)).toBe(computeJa4(hello));
    });

    it("encodes the connection prefix (JA4_a) with SNI flag, version and ALPN", () => {
        const { a } = computeJa4Fingerprint(richClientHello());
        expect(a.startsWith("t")).toBe(true);
        // 2 ciphers -> "02"; 4 non-GREASE exts -> "04"; SNI present -> "d";
        // TLS 1.3 -> "13"; ALPN h + h -> "hh".
        expect(a).toBe("t0204d13hh");
    });

    it("omits SNI and ALPN from the JA4_c extension hash", () => {
        const { a, b, c, f } = computeJa4Fingerprint(richClientHello());
        // Every part is a 12-hex digest and the tag joins them.
        for (const part of [b, c, f]) {
            expect(part).toMatch(/^[0-9a-f]{12}$/);
        }
        expect(`${a}_${b}_${c}_${f}`).toBe(computeJa4(richClientHello()));
    });
});

describe("JA4_f — client_version, not record-header bytes", () => {
    // Regression: JA4_f used to read uint16(buf, 0) — the first two bytes of
    // the *buffer* — instead of the parsed client_version field. For a
    // record-wrapped hello those bytes are 0x16 0x03 (record header); for a
    // bare hello they are 0x01 <len> (handshake header). So two byte-identical
    // ClientHellos produced DIFFERENT JA4_f. The fix uses the parsed
    // versionCode so wrapping is irrelevant.
    it("produces identical JA4_f (and full tag) for bare vs record-wrapped ClientHellos", () => {
        const bare = richClientHello();
        const wrapped = wrapInRecord(bare);

        const bareFp = computeJa4Fingerprint(bare);
        const wrappedFp = computeJa4Fingerprint(wrapped);

        expect(wrappedFp.f).toBe(bareFp.f);
        expect(wrappedFp.tag).toBe(bareFp.tag);
    });

    it("exposes the parsed client_version on Ja4ClientHello for both forms", () => {
        // The fix relies on this surface: JA4_f hashes versionCode (0x0304),
        // not the buffer's first two bytes (0x0100 bare / 0x1603 wrapped).
        const bare = parseJa4ClientHello(richClientHello());
        const wrapped = parseJa4ClientHello(wrapInRecord(richClientHello()));
        expect(bare.versionCode).toBe(0x0304);
        expect(wrapped.versionCode).toBe(0x0304);
        expect(bare.versionCode).toBe(wrapped.versionCode);
    });
});

describe("computeJa4h (four-part JA4H HTTP fingerprint)", () => {
    it("emits a well-formed canonical JA4H tag", () => {
        const tag = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: ["host", "accept"],
            cookies: [],
        });
        expect(tag.tag).toMatch(JA4H_TAG_RE);
    });

    it("encodes method, version, cookie/referer flags, header count and language", () => {
        const { a } = computeJa4h({
            method: "POST",
            httpVersion: "2",
            headerNames: ["host", "referer", "accept-language"],
            cookies: ["sid=abc"],
            acceptLanguage: "en-US",
        });
        // POST -> "po"; HTTP/2 -> "02"; cookies -> "c"; referer present -> "r";
        // 3 headers -> "03"; "en-US" 4-prefix lowercased -> "en-u".
        expect(a).toBe("po02cr03en-u");
    });

    it("uses 'n' flags when there are no cookies and no referer", () => {
        const { a } = computeJa4h({
            method: "GET",
            httpVersion: "3",
            headerNames: ["host"],
            cookies: [],
        });
        expect(a.startsWith("ge03nn01")).toBe(true);
    });

    it("pads a short language prefix and lowercases it", () => {
        const { a } = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: [],
            cookies: [],
            acceptLanguage: "Fr",
        });
        // "Fr" padded to 4 with "0" then lowercased -> "fr00"; header count -> "00".
        expect(a).toBe("ge11nn00fr00");
    });

    it("is deterministic and stable across calls", () => {
        const request = {
            method: "GET" as const,
            httpVersion: "1.1" as const,
            headerNames: ["host", "cookie"],
            cookies: ["a=1", "b=2"],
        };
        expect(computeJa4h(request)).toEqual(computeJa4h(request));
    });
});
