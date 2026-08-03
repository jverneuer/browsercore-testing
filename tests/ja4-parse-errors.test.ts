/**
 * Tests for JA4 ClientHello parser error branches + early-return / edge paths
 * (src/fingerprint/ja4.ts).
 *
 * ja4.test.ts covers the happy path with a rich ClientHello. This file
 * exercises every Ja4ParseError throw site reachable through the public API,
 * the no-extensions early return, the unknown-TLS-version fallback, the ALPN
 * code derivation, and the record-wrapped computeJa4 path.
 */

import { describe, expect, it } from "vitest";
import {
    computeJa4,
    computeJa4Fingerprint,
    Ja4ParseError,
    parseJa4ClientHello,
} from "../src/fingerprint/ja4.js";

/** Build a bare ClientHello (handshake type 0x01) from body segments. */
function buildBare(segments: readonly number[][], handshakeLenOverride?: number): Uint8Array {
    const body: number[] = [];
    for (const seg of segments) {
        body.push(...seg);
    }
    const len = handshakeLenOverride ?? body.length;
    return new Uint8Array([
        0x01,
        (len >> 16) & 0xff,
        (len >> 8) & 0xff,
        len & 0xff,
        ...body,
    ]);
}

/** Wrap a bare handshake in a TLS record (ContentType 0x16). */
function wrapRecord(handshake: Uint8Array): Uint8Array {
    return new Uint8Array([
        0x16,
        0x03,
        0x01,
        (handshake.length >> 8) & 0xff,
        handshake.length & 0xff,
        ...handshake,
    ]);
}

const VERSION = [0x03, 0x04]; // TLS 1.3
const RANDOM = Array.from({ length: 32 }, (_, i) => i);
const NO_SESSION = [0x00];
const ONE_CIPHER = [0x00, 0x02, 0x13, 0x01];
const NO_COMP = [0x01, 0x00];

describe("parseJa4ClientHello — top-level shape errors", () => {
    it("throws when the input is empty", () => {
        expect(() => parseJa4ClientHello(new Uint8Array(0))).toThrow(/ClientHello is empty/);
    });

    it("throws for an unknown first byte (neither record nor ClientHello)", () => {
        expect(() => parseJa4ClientHello(new Uint8Array([0xff, 0xff]))).toThrow(
            /Not a TLS record or ClientHello/,
        );
    });
});

describe("parseJa4ClientHello — record-wrapper errors", () => {
    it("throws when the TLS record header is too short", () => {
        expect(() => parseJa4ClientHello(new Uint8Array([0x16, 0x03, 0x01]))).toThrow(
            /TLS record too short/,
        );
    });

    it("throws when uint24 for the handshake length runs past the buffer", () => {
        // Record header ok + ClientHello byte present, but the 3-byte length is
        // truncated.
        const bad = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x02, 0x01]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/uint24 read out of bounds/);
    });

    it("throws when the handshake type after the record header is not ClientHello", () => {
        const bad = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x02, 0x02]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Expected ClientHello/);
    });

    it("throws when the declared handshake length exceeds available bytes", () => {
        const bad = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0xff]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Handshake length \d+ exceeds available/);
    });
});

describe("parseJa4ClientHello — bare-handshake errors", () => {
    it("throws when a bare ClientHello is shorter than 4 bytes", () => {
        expect(() => parseJa4ClientHello(new Uint8Array([0x01, 0x00, 0x00]))).toThrow(
            /Bare ClientHello too short/,
        );
    });

    it("throws when the declared handshake length exceeds available bytes", () => {
        const bad = new Uint8Array([0x01, 0x00, 0x00, 0xff, 0x03]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Handshake length \d+ exceeds available/);
    });

    it("throws when too short for the version field", () => {
        // handshakeLen = 0 → end == pos → pos + 2 > end.
        const bad = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/too short for version/);
    });

    it("throws when truncated before the session id (random overrun)", () => {
        // handshakeLen = 2: version fits, but random(32) runs past end.
        const bad = new Uint8Array([0x01, 0x00, 0x00, 0x02, 0x03, 0x04]);
        expect(() => parseJa4ClientHello(bad)).toThrow(/truncated before session id/);
    });

    it("throws when truncated at the session-id length byte", () => {
        // version + random = 34 body bytes, handshakeLen = 34, no session byte.
        const truncated = buildBare([VERSION, RANDOM], 34);
        expect(() => parseJa4ClientHello(truncated)).toThrow(/truncated at session id length/);
    });

    it("throws when truncated before the cipher suites", () => {
        // version + random + session_id(len 0) = 35 body bytes, handshakeLen=35.
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION], 35);
        expect(() => parseJa4ClientHello(truncated)).toThrow(/truncated before cipher suites/);
    });

    it("throws when truncated inside the cipher suites", () => {
        // version+random+session+cipher_suites_len(claims 4) = 37 body bytes,
        // but only the 2-byte length field is present (no suite bytes).
        const cipherLenField = [0x00, 0x04]; // claims 4 bytes of suites
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION, cipherLenField], 37);
        expect(() => parseJa4ClientHello(truncated)).toThrow(/truncated in cipher suites/);
    });

    it("throws when truncated before the compression methods", () => {
        // Through cipher suites (len 2, one suite), handshakeLen = 39 → end
        // leaves no room for even the compression-length byte.
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER], 39);
        expect(() => parseJa4ClientHello(truncated)).toThrow(
            /truncated before compression methods/,
        );
    });
});

describe("parseJa4ClientHello — no-extensions early return", () => {
    it("returns empty extensions/groups/ec/alpn when no extensions follow compression", () => {
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.tlsVersion).toBe("13");
        expect(parsed.sniPresent).toBe(false);
        expect(parsed.cipherSuites).toEqual([0x1301]);
        expect(parsed.extensions).toEqual([]);
        expect(parsed.supportedGroups).toEqual([]);
        expect(parsed.ecPointFormats).toEqual([]);
        expect(parsed.alpnRaw).toBe("");
    });

    it("computeJa4 yields a valid tag with no ALPN (alpnCode '00')", () => {
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const { a } = computeJa4Fingerprint(hello);
        // 1 cipher, 0 extensions, no SNI -> "i", TLS 1.3 -> "13", no ALPN -> "00".
        expect(a).toBe("t0100i1300");
    });
});

describe("parseJa4ClientHello — version + ALPN edge cases", () => {
    it("falls back to a hex string for an unknown TLS version", () => {
        // version 0x0029 (41) is not in TLS_VERSIONS → "29".
        const hello = buildBare([[0x00, 0x29], RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.tlsVersion).toBe("29");
    });

    it("encodes a single-protocol ALPN as first+last char of that protocol", () => {
        // ALPN with just "h2" → alpnRaw "h2" → alpnCode "hh".
        const alpn = [
            0x00, 0x10, 0x00, 0x05, // ext type ALPN, len 5
            0x00, 0x03, // list len 3
            0x02, 0x68, 0x32, // "h2"
        ];
        const extLen = [0x00, alpn.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLen,
            alpn,
        ]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.alpnRaw).toBe("h2");
        const { a } = computeJa4Fingerprint(hello);
        expect(a.endsWith("hh")).toBe(true);
    });

    it("encodes no-SNI with the 'i' flag", () => {
        // supported_groups present but no SNI → sniPresent false.
        const groups = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
        const extLen = [0x00, groups.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLen,
            groups,
        ]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.sniPresent).toBe(false);
        expect(parsed.extensions).toContain(0x000a);
        const { a } = computeJa4Fingerprint(hello);
        expect(a).toContain("i");
    });

    it("throws Ja4ParseError when the ALPN protocol list is truncated", () => {
        // ALPN ext claims listLen=1 but the protocol-length byte is missing.
        const alpn = [
            0x00, 0x10, 0x00, 0x02, // ext type ALPN, extLen 2 (just the list-len field)
            0x00, 0x01, // list len claims 1 byte of protocols, but none follow
        ];
        const extLen = [0x00, alpn.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLen,
            alpn,
        ]);
        expect(() => parseJa4ClientHello(hello)).toThrow(/truncated at ALPN protocol length/);
    });
});

describe("parseJa4ClientHello — ec_point_formats list truncation", () => {
    it("throws when the ec_point_formats list claims more bytes than present", () => {
        // ec_point_formats ext with extLen=2 (listLen byte + 1 format), but
        // listLen claims 5 formats — the read runs off the buffer.
        const ecExt = [
            0x00, 0x0b, 0x00, 0x02, // ext type ec_point_formats, extLen 2
            0x05, // listLen claims 5 formats
            0x00, // only 1 format byte follows
        ];
        const extLen = [0x00, ecExt.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLen,
            ecExt,
        ]);
        expect(() => parseJa4ClientHello(hello)).toThrow(
            /truncated in ec_point_formats list/,
        );
    });
});

describe("computeJa4Fingerprint — empty cipher suites", () => {
    it("produces the zero-hash JA4_b when no cipher suites are present", () => {
        // cipher_suites_len = 0 → no suites → JA4_b is the all-zero sentinel.
        const emptyCiphers = [0x00, 0x00];
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, emptyCiphers, NO_COMP]);
        const { b } = computeJa4Fingerprint(hello);
        expect(b).toBe("000000000000");
    });
});

describe("parseJa4ClientHello — unknown version with full extension parse", () => {
    it("falls back to a hex version string in the full-parse return path", () => {
        // Unknown version (0x0029) WITH extensions, so the full return at the
        // end of parseJa4ClientHello is reached (not the no-extensions early
        // return).
        const groups = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
        const extLen = [0x00, groups.length];
        const hello = buildBare([
            [0x00, 0x29], // unknown version 0x0029
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLen,
            groups,
        ]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.tlsVersion).toBe("29");
        expect(parsed.extensions).toContain(0x000a);
    });
});

describe("parseJa4ClientHello — GREASE filtering", () => {
    it("drops GREASE cipher suites and extension types", () => {
        const greaseSuite = [0x0a, 0x0a]; // GREASE per RFC 8701
        const greaseExt = [0x1a, 0x1a, 0x00, 0x00]; // GREASE ext type + empty body
        const realExt = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]; // supported_versions
        const extensions = [...greaseExt, ...realExt];
        const extLen = [0x00, extensions.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            [0x00, 0x04, ...greaseSuite, 0x13, 0x01], // len 4: GREASE + real suite
            NO_COMP,
            extLen,
            extensions,
        ]);
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.cipherSuites).toEqual([0x1301]);
        expect(parsed.extensions).toEqual([0x002b]);
    });
});

describe("computeJa4 — record-wrapped ClientHello", () => {
    it("parses a record-wrapped ClientHello and matches the bare JA4_a/b/c parts", () => {
        const bare = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const wrapped = wrapRecord(bare);
        const bareFp = computeJa4Fingerprint(bare);
        const wrappedFp = computeJa4Fingerprint(wrapped);
        // a/b/c are derived from parsed fields (identical after record stripping).
        expect(wrappedFp.a).toBe(bareFp.a);
        expect(wrappedFp.b).toBe(bareFp.b);
        expect(wrappedFp.c).toBe(bareFp.c);
        // JA4_f hashes the raw first 2 bytes of the input buffer, which differ
        // (0x16 0x03 for the record header vs 0x01 .. for the bare handshake),
        // so the f part is expected to differ.
        expect(wrappedFp.tag).toMatch(/^t\d{2}\d{2}[di]\d{2}[a-z0-9]{2}_[a-z0-9]{12}_[a-z0-9]{12}_[a-z0-9]{12}$/);
    });

    it("throws Ja4ParseError for malformed input", () => {
        expect(() => computeJa4(new Uint8Array([0xff]))).toThrow(Ja4ParseError);
    });
});
