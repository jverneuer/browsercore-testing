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
