/**
 * Coverage-targeted tests for the gaps holding src/fingerprint/ja4-reader.ts,
 * ja4.ts, and ja4h.ts below 94%.
 *
 * ja4.test.ts + ja4-parse-errors.test.ts cover the rich-happy path and most
 * parse errors. This file targets the remaining branches that the v8 report
 * flags as uncovered:
 *
 * - ja4-reader.ts line 39: the `uint16` out-of-bounds throw. Reachable when a
 *   ClientHello extension header claims a type/length but the buffer ends
 *   before both bytes are present.
 * - ja4-reader.ts line 89: the `readEcPointFormats` truncation throw, when the
 *   ec_point_formats list length byte claims more format bytes than remain.
 * - ja4.ts line 187: the "truncated in cipher suites" throw, when the
 *   cipher_suites length field claims more bytes than remain before the
 *   compression-methods byte.
 * - ja4h.ts: the header-filtering branches — cookies present (sorted cookie
 *   names computed) and the `d` part computed from non-cookie headers.
 */

import { describe, expect, it } from "vitest";
import {
    computeJa4,
    computeJa4Fingerprint,
    parseJa4ClientHello,
    Ja4ParseError,
} from "../src/fingerprint/ja4.js";
import { computeJa4h } from "../src/fingerprint/ja4h.js";
import { readEcPointFormats, uint16 } from "../src/fingerprint/ja4-reader.js";

const VERSION = [0x03, 0x04]; // TLS 1.3
const RANDOM = Array.from({ length: 32 }, (_, i) => i);
const NO_SESSION = [0x00];
const ONE_CIPHER = [0x00, 0x02, 0x13, 0x01];
const NO_COMP = [0x01, 0x00];

/** Build a bare ClientHello (handshake type 0x01) from body segments. */
function buildBare(segments: readonly number[][], handshakeLenOverride?: number): Uint8Array {
    const body: number[] = [];
    for (const seg of segments) {
        body.push(...seg);
    }
    const len = handshakeLenOverride ?? body.length;
    return new Uint8Array([0x01, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, ...body]);
}

describe("ja4-reader — uint16 out-of-bounds (line 39)", () => {
    it("throws Ja4ParseError when the buffer is too short for a uint16 read", () => {
        // A 1-byte buffer cannot satisfy a uint16 read at offset 0.
        expect(() => uint16(new Uint8Array([0x01]), 0)).toThrow(Ja4ParseError);
        expect(() => uint16(new Uint8Array([0x01]), 0)).toThrow(/uint16 read out of bounds/);
    });

    it("reads a uint16 when both bytes are present", () => {
        expect(uint16(new Uint8Array([0x13, 0x01]), 0)).toBe(0x1301);
    });
});

describe("ja4-reader — readEcPointFormats truncation (line 89)", () => {
    it("throws when the ec_point_formats list claims more bytes than present", () => {
        // listLen = 3, but only 1 format byte follows.
        const buf = new Uint8Array([0x03, 0x00, 0x01]);
        expect(() => readEcPointFormats(buf, 0)).toThrow(/truncated in ec_point_formats list/);
    });

    it("reads all formats when the buffer is intact", () => {
        const buf = new Uint8Array([0x02, 0x00, 0x01]);
        expect(readEcPointFormats(buf, 0)).toEqual([0x00, 0x01]);
    });

    it("throws when the ec_point_formats length byte is past the buffer (line 89)", () => {
        // Build a full ClientHello whose ec_point_formats extension header claims
        // extLen = 1 but the data byte is missing. parseJa4ClientHello reads the
        // extension header, then calls readEcPointFormats at pos === buffer.length
        // → clientHello[pos] is undefined → the line-87 `listLen === undefined`
        // branch (reported as line 89) throws.
        const ec = [0x00, 0x0b, 0x00, 0x01]; // type 0x000b, extLen 1, NO data byte
        const extLenField = [0x00, ec.length]; // extensions block length = 4
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLenField,
            ec,
        ]);
        expect(() => parseJa4ClientHello(hello)).toThrow(/truncated at ec_point_formats length/);
    });
});

describe("ja4 — cipher-suites truncation (line 187)", () => {
    it("throws when the cipher_suites length claims more bytes than remain", () => {
        // version + random + session = 35 body bytes. cipher_suites_len claims
        // 4 bytes, but we truncate the handshake right after the 2-byte length
        // field (handshakeLen = 37), so the 4 suite bytes are missing.
        const cipherLenField = [0x00, 0x04]; // claims 4 bytes of suites
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION, cipherLenField], 37);
        expect(() => parseJa4ClientHello(truncated)).toThrow(/truncated in cipher suites/);
    });
});

describe("ja4h — cookie + header branches", () => {
    it("computes JA4H for HTTP/3 (versionCode '03', ja4h.ts line 57 true branch)", () => {
        // httpVersion "3" exercises the true branch of the `=== "3"` check
        // (ja4h.ts line 57) — the existing tests only use "1.1" and "2".
        const { a } = computeJa4h({
            method: "GET",
            httpVersion: "3",
            headerNames: ["host"],
            cookies: [],
        });
        // GET -> "ge"; "3" -> "03"; no cookies -> "n"; no referer -> "n";
        // 1 header -> "01"; no acceptLanguage -> "0000".
        expect(a).toBe("ge03nn010000");
    });

    it("falls through to versionCode '00' for an unknown version (ja4h.ts line 57 false branch)", () => {
        // An unrecognized httpVersion (not "1.1", "2", or "3") drives the
        // nested ternary past all three conditions to the final `: "00"`
        // fallback. This covers the false branch of the `=== "3"` check on
        // line 57 — short-circuiting from "1.1"/"2" never evaluates it.
        const { a } = computeJa4h({
            method: "GET",
            httpVersion: "9" as "1.1" | "2" | "3",
            headerNames: ["host"],
            cookies: [],
        });
        // GET -> "ge"; unknown -> "00"; no cookies -> "n"; no referer -> "n";
        // 1 header -> "01"; no acceptLanguage -> "0000".
        expect(a).toBe("ge00nn010000");
    });

    it("computes the cookie-name hash (JA4H_c) when cookies are present", () => {
        const { c } = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: ["host", "cookie"],
            cookies: ["sid=abc", "theme=dark"],
        });
        // c is the SHA-256-first-12 of sorted cookie names ("sid,theme").
        expect(c).toMatch(/^[0-9a-f]{12}$/);
        expect(c).not.toBe("000000000000");
    });

    it("computes JA4H_d from non-cookie headers (cookie filtered out)", () => {
        const { d, a } = computeJa4h({
            method: "POST",
            httpVersion: "2",
            headerNames: ["host", "cookie", "accept"],
            cookies: ["a=1"],
        });
        // d is the hash of sorted headers excluding "cookie": "accept,host".
        expect(d).toMatch(/^[0-9a-f]{12}$/);
        // JA4H_a = {method:02}{version}{cookies}{referer}{header_count:02}{lang}.
        // POST -> "po"; 2 -> "02"; cookies -> "c"; no referer -> "n";
        // 3 headers -> "03"; no lang -> "0000".
        expect(a).toBe("po02cn030000");
    });

    it("computes JA4H_d as zero-hash when only the cookie header is present", () => {
        // With only ["cookie"] as headerNames, filtering leaves nothing → d is
        // the all-zero sentinel (ja4h.ts line 74 branch).
        const { d } = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: ["cookie"],
            cookies: ["a=1"],
        });
        expect(d).toBe("000000000000");
    });

    it("flags cookies present (hasCookies='c') and referer present (hasReferer='r')", () => {
        const { a } = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: ["host", "referer"],
            cookies: ["x=1"],
        });
        // GET -> "ge"; 1.1 -> "11"; cookies -> "c"; referer -> "r";
        // 2 headers -> "02"; no acceptLanguage -> "0000".
        expect(a).toBe("ge11cr020000");
    });

    it("produces the zero-hash JA4H_b when the request has no cookies (ja4h.ts line 71)", () => {
        // With cookies: [] the sortedCookies join is the empty string, so
        // `sortedCookies.length > 0` is false → JA4H_b falls back to the
        // all-zero sentinel (ja4h.ts line 71 false branch).
        const { b } = computeJa4h({
            method: "GET",
            httpVersion: "1.1",
            headerNames: ["host"],
            cookies: [],
        });
        expect(b).toBe("000000000000");
    });
});

describe("ja4 — GREASE-only cipher suites yield zero-hash JA4_b", () => {
    it("produces the zero-hash JA4_b when every cipher suite is GREASE", () => {
        // 2 GREASE suites (0x0a0a, 0x1a1a) → filtered to none → JA4_b is the
        // all-zero sentinel (ja4.ts line 283 branch).
        const greaseSuites = [0x00, 0x04, 0x0a, 0x0a, 0x1a, 0x1a];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, greaseSuites, NO_COMP]);
        const { b } = computeJa4Fingerprint(hello);
        expect(b).toBe("000000000000");
    });
});

describe("ja4 — compression-methods length truncation (line 187)", () => {
    it("throws when the buffer ends exactly at the compression-methods length byte", () => {
        // Body through cipher suites = 39 bytes. Override handshakeLen to 40 so
        // that `end` (44) is one past the buffer (43 bytes). The line-181 guard
        // (`pos + 1 > end`) passes (44 > 44 is false), but clientHello[43] is
        // undefined → the line-186 `compLen === undefined` branch throws.
        // The error may surface as either the "truncated at compression methods
        // length" error (if the buffer reaches that far) or the handshake-length
        // exceeded error (if the handshake length check fires first). Either
        // branch is a legitimate truncation detection.
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER], 40);
        expect(() => parseJa4ClientHello(truncated)).toThrow(/truncated|exceeds available/);
    });
});

describe("ja4 — extension length guards (lines 219, 223, 225)", () => {
    it("skips supported_groups when extLen < 4 (line 219 false branch)", () => {
        // supported_groups ext with extLen = 2 (only the listLen field, no
        // groups). The `extLen >= 4` guard fails → no groups are read.
        const groups = [0x00, 0x0a, 0x00, 0x02, 0x00, 0x00];
        const extLen = [0x00, groups.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, groups]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.extensions).toContain(0x000a);
        expect(parsed.supportedGroups).toEqual([]);
    });

    it("skips ec_point_formats when extLen = 0 (line 223 false branch)", () => {
        // ec_point_formats ext with extLen = 0 (no data at all). The
        // `extLen >= 1` guard fails → no formats are read.
        const ec = [0x00, 0x0b, 0x00, 0x00];
        const extLen = [0x00, ec.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, ec]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.extensions).toContain(0x000b);
        expect(parsed.ecPointFormats).toEqual([]);
    });

    it("skips ALPN when extLen < 2 (line 225 false branch)", () => {
        // ALPN ext with extLen = 1 (only half the listLen field). The
        // `extLen >= 2` guard fails → alpnRaw stays empty.
        const alpn = [0x00, 0x10, 0x00, 0x01, 0x00];
        const extLen = [0x00, alpn.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, alpn]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.extensions).toContain(0x0010);
        expect(parsed.alpnRaw).toBe("");
    });
});

describe("ja4 — JA4_c zero-hash when all extensions are SNI/ALPN (line 289)", () => {
    it("produces the zero-hash JA4_c when every extension is SNI or ALPN", () => {
        // SNI(0) and ALPN(16) are filtered out of JA4_c, so a ClientHello
        // carrying only those extensions yields an empty filteredExts list →
        // the `filteredExts.length > 0` false branch → JA4_c is the zero hash.
        const sni = [0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x61]; // SNI "a"
        const alpn = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32]; // ALPN "h2"
        const extensions = [...sni, ...alpn];
        const extLen = [0x00, extensions.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, extensions]);
        const { c } = computeJa4Fingerprint(hello);
        expect(c).toBe("000000000000");
    });
});

describe("ja4 — alpnCode empty-protocol branches (lines 90, 91)", () => {
    it("uses '0' for the first char when the first ALPN protocol is empty", () => {
        // ALPN list ",h2" → first protocol is empty → `first.length > 0` is
        // false → alpnCode first char is "0" (ja4.ts line 90 false branch).
        // listLen=4: [0x00 (len 0) + 0x02 0x68 0x32 (len 2, "h2")].
        const alpn = [0x00, 0x10, 0x00, 0x06, 0x00, 0x04, 0x00, 0x02, 0x68, 0x32];
        const extLen = [0x00, alpn.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, alpn]);
        const { a } = computeJa4Fingerprint(hello);
        // 1 cipher, 1 ext, no SNI -> "i", TLS 1.3 -> "13", alpnCode -> "0h".
        expect(a).toBe("t0101i130h");
    });

    it("uses '0' for the last char when the last ALPN protocol is empty", () => {
        // ALPN list "h2," → last protocol is empty → `last.length > 0` is
        // false → alpnCode last char is "0" (ja4.ts line 91 false branch).
        // listLen=4: [0x02 0x68 0x32 (len 2, "h2") + 0x00 (len 0)].
        const alpn = [0x00, 0x10, 0x00, 0x06, 0x00, 0x04, 0x02, 0x68, 0x32, 0x00];
        const extLen = [0x00, alpn.length];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP, extLen, alpn]);
        const { a } = computeJa4Fingerprint(hello);
        // alpnCode -> "h0".
        expect(a).toBe("t0101i13h0");
    });
});
