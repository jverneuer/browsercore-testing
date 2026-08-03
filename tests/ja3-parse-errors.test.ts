/**
 * Tests for JA3 ClientHello parser error branches + early-return paths
 * (src/fingerprint/ja3.ts).
 *
 * ja3.test.ts covers the happy paths (bare + record-wrapped + groups/EC
 * extensions). This file exercises every Ja3ParseError throw site and the
 * no-extensions early return, which together account for most of the
 * remaining uncovered lines.
 */

import { describe, expect, it } from "vitest";
import { computeJa3, Ja3ParseError, parseClientHello } from "../src/fingerprint/ja3.js";

/**
 * Build a bare (handshake-only) ClientHello body from segments, prefixed with
 * the 4-byte handshake header (type 0x01 + 24-bit length). The header length
 * defaults to the true body length but can be overridden to test length
 * validation.
 */
function buildBare(
    segments: readonly number[][],
    handshakeLenOverride?: number,
): Uint8Array {
    const body: number[] = [];
    for (const seg of segments) {
        body.push(...seg);
    }
    const len = handshakeLenOverride ?? body.length;
    return new Uint8Array([
        0x01, // handshake type: ClientHello
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

const VERSION = [0x03, 0x03];
const RANDOM = Array.from({ length: 32 }, (_, i) => i);
const NO_SESSION = [0x00]; // session_id length = 0
const ONE_CIPHER = [0x00, 0x02, 0x13, 0x01]; // len=2, TLS_AES_128_GCM_SHA256
const NO_COMP = [0x01, 0x00]; // len=1, null compression

describe("parseClientHello — record-wrapper errors", () => {
    it("throws when the TLS record header is too short (< 5 bytes)", () => {
        expect(() => parseClientHello(new Uint8Array([0x16, 0x03, 0x01]))).toThrow(
            /TLS record too short/,
        );
    });

    it("throws when the handshake type after the record header is not ClientHello", () => {
        // Record version(2) + length(2) = 0x0002, then body byte 0x02 (not 0x01).
        const bad = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x02, 0x02]);
        expect(() => parseClientHello(bad)).toThrow(/Expected ClientHello/);
    });

    it("throws when readInt24 runs past the buffer (truncated record)", () => {
        // Record header ok, ClientHello byte present, but the 3-byte handshake
        // length field is truncated.
        const bad = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x02, 0x01]);
        expect(() => parseClientHello(bad)).toThrow(Ja3ParseError);
    });

    it("throws when the declared handshake length exceeds the available bytes", () => {
        // Record declares a 0x00FF body but only a few bytes follow.
        const bad = new Uint8Array([
            0x16, 0x03, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0xff, 0x03, 0x03,
        ]);
        expect(() => parseClientHello(bad)).toThrow(/Handshake length \d+ exceeds available/);
    });
});

describe("parseClientHello — bare-handshake errors", () => {
    it("throws when readInt24 runs past the buffer (1-byte input)", () => {
        expect(() => parseClientHello(new Uint8Array([0x01]))).toThrow(/readInt24 out of bounds/);
    });

    it("throws when the declared handshake length exceeds the available bytes", () => {
        // handshakeLen = 0x0000ff = 255, but only 1 body byte follows.
        const bad = new Uint8Array([0x01, 0x00, 0x00, 0xff, 0x03]);
        expect(() => parseClientHello(bad)).toThrow(/Handshake length \d+ exceeds available/);
    });

    it("throws when uint16 for the version reads out of bounds", () => {
        // handshakeLen = 1 (passes the available check), but only 1 body byte —
        // the version uint16 needs 2 bytes.
        const bad = new Uint8Array([0x01, 0x00, 0x00, 0x01, 0x03]);
        expect(() => parseClientHello(bad)).toThrow(/uint16 read out of bounds/);
    });

    it("throws when truncated at the session-id length byte", () => {
        // Body has version + random (34 bytes) but no session-id length byte.
        // handshakeLen = 34 == available, so the length check passes.
        const truncated = buildBare([VERSION, RANDOM], 34);
        expect(truncated.length).toBe(4 + 34);
        expect(() => parseClientHello(truncated)).toThrow(/truncated at session id length/);
    });

    it("throws when truncated at the compression-methods length byte", () => {
        // version + random + session_id(0) + cipher_suites(len 2) = 39 body bytes.
        const truncated = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER], 39);
        expect(() => parseClientHello(truncated)).toThrow(/truncated at compression methods length/);
    });
});

describe("parseClientHello — no-extensions early return", () => {
    it("returns empty extension/group/ecPoint segments when no extensions follow compression", () => {
        // A complete ClientHello whose handshake body ends right after the
        // compression methods — pos + 2 > end triggers the early return.
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const seg = parseClientHello(hello);
        expect(seg.version).toBe("771");
        expect(seg.ciphers).toBe("4865");
        expect(seg.extensions).toBe("");
        expect(seg.supportedGroups).toBe("");
        expect(seg.ecPointFormats).toBe("");
    });

    it("computeJa3 still produces a valid digest for an extension-less ClientHello", () => {
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const digest = computeJa3(hello);
        expect(digest).toMatch(/^[0-9a-f]{32}$/);
    });
});

describe("parseClientHello — readUint16List out of bounds", () => {
    it("throws when cipher_suites_len claims more bytes than the buffer holds", () => {
        // version + random + session_id(len 0) + cipher_suites_len(claims 16)
        // followed by only one real suite (2 bytes). ja3 has no cipher-length
        // guard, so readUint16List runs off the buffer.
        const inflatedLen = [0x00, 0x10]; // claims 16 bytes of suites
        const hello = buildBare([VERSION, RANDOM, NO_SESSION, inflatedLen, [0x13, 0x01]]);
        expect(() => parseClientHello(hello)).toThrow(/readUint16List out of bounds/);
    });
});

describe("parseClientHello — extension parsing errors", () => {
    it("throws when the ec_point_formats list-length byte is missing", () => {
        // Extensions block declares an ec_point_formats(0x000b) ext with len 1,
        // but the body byte (list length) is truncated away.
        const extHeader = [0x00, 0x0b, 0x00, 0x01]; // type, len=1
        const extLenField = [0x00, 0x04]; // extensions length = 4 (just the header)
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLenField,
            extHeader,
        ]);
        expect(() => parseClientHello(hello)).toThrow(/truncated at ec_point_formats length/);
    });

    it("throws when the ec_point_formats list itself is truncated", () => {
        // ec_point_formats declares list_len=2 but only 1 format byte follows.
        const ext = [0x00, 0x0b, 0x00, 0x03, 0x02, 0x00]; // type, extLen=3, listLen=2, one fmt
        const extLenField = [0x00, ext.length];
        const hello = buildBare([
            VERSION,
            RANDOM,
            NO_SESSION,
            ONE_CIPHER,
            NO_COMP,
            extLenField,
            ext,
        ]);
        expect(() => parseClientHello(hello)).toThrow(/truncated in ec_point_formats list/);
    });
});

describe("parseClientHello — record-wrapped happy path", () => {
    it("parses a record-wrapped ClientHello and yields the same digest as the bare form", () => {
        const bare = buildBare([VERSION, RANDOM, NO_SESSION, ONE_CIPHER, NO_COMP]);
        const wrapped = wrapRecord(bare);
        expect(computeJa3(wrapped)).toBe(computeJa3(bare));
    });
});
