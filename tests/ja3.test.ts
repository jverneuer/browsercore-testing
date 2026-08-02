/**
 * Real tests for JA3 computation (Cat 4).
 *
 * Verifies {@link parseClientHello} extracts the five JA3 segments and that
 * {@link computeJa3} is the MD5 of the canonical ja3 string — checked against
 * an independently computed digest in the test (no magic expected values).
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { computeJa3, Ja3ParseError, parseClientHello } from "../src/fingerprint/ja3.js";

/** Build a minimal, well-formed TLS 1.3 ClientHello (no record wrapper). */
function sampleClientHello(): Uint8Array {
    const body = [
        0x03, 0x03, // client_version = 0x0303
        // random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
        0x00, // session_id length = 0
        0x00, 0x02, // cipher_suites length = 2
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x01, // compression_methods length = 1
        0x00, // null compression
        0x00, 0x06, // extensions length = 6
        // supported_versions(0x002b) length 2: version 0x0304
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
    ];
    const handshakeLen = body.length;
    return new Uint8Array([
        0x01, // handshake type: ClientHello
        (handshakeLen >> 16) & 0xff,
        (handshakeLen >> 8) & 0xff,
        handshakeLen & 0xff,
        ...body,
    ]);
}

describe("parseClientHello", () => {
    it("extracts the five JA3 segments from a bare ClientHello", () => {
        const segments = parseClientHello(sampleClientHello());
        expect(segments.version).toBe("771"); // 0x0303
        expect(segments.ciphers).toBe("4865"); // 0x1301
        expect(segments.extensions).toBe("43"); // 0x002b
        expect(segments.supportedGroups).toBe("");
        expect(segments.ecPointFormats).toBe("");
    });

    it("parses a ClientHello wrapped in a TLS record", () => {
        const handshake = sampleClientHello();
        const record = new Uint8Array([
            0x16, // content type: handshake
            0x03, 0x01, // record version
            (handshake.length >> 8) & 0xff,
            handshake.length & 0xff,
            ...handshake,
        ]);
        const segments = parseClientHello(record);
        expect(segments.version).toBe("771");
        expect(segments.ciphers).toBe("4865");
    });

    it("throws Ja3ParseError on garbage input", () => {
        const garbage = new Uint8Array([0xff, 0xff, 0xff]);
        expect(() => parseClientHello(garbage)).toThrow(Ja3ParseError);
    });

    // Exercises the supported_groups(0x000a) and ec_point_formats(0x000b)
    // extension parsers (ja3.ts lines 131-139) which the minimal sample does not
    // reach.
    it("parses supported_groups and ec_point_formats extensions", () => {
        const body = [
            0x03, 0x03, // client_version = 0x0303
            // random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
            0x00, // session_id length = 0
            0x00, 0x02, // cipher_suites length = 2
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x01, // compression_methods length = 1
            0x00, // null compression
            0x00, 0x0e, // extensions length = 14
            // supported_groups(0x000a): list_len=2, one group 0x001d
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
            // ec_point_formats(0x000b): list_len=1, format 0x00 uncompressed
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        ];
        const handshakeLen = body.length;
        const hello = new Uint8Array([
            0x01, // handshake type: ClientHello
            (handshakeLen >> 16) & 0xff,
            (handshakeLen >> 8) & 0xff,
            handshakeLen & 0xff,
            ...body,
        ]);
        const segments = parseClientHello(hello);
        expect(segments.version).toBe("771"); // 0x0303
        expect(segments.ciphers).toBe("4865"); // 0x1301
        expect(segments.extensions).toBe("10-11"); // 0x000a, 0x000b
        expect(segments.supportedGroups).toBe("29"); // 0x001d
        expect(segments.ecPointFormats).toBe("0"); // uncompressed
    });
});

describe("computeJa3", () => {
    it("equals the MD5 of the canonical ja3 string", () => {
        const hello = sampleClientHello();
        const segments = parseClientHello(hello);
        const canonical = [
            segments.version,
            segments.ciphers,
            segments.extensions,
            segments.supportedGroups,
            segments.ecPointFormats,
        ].join(",");
        const expected = createHash("md5").update(canonical).digest("hex");
        expect(computeJa3(hello)).toBe(expected);
    });

    it("is a 32-hex-char digest and deterministic", () => {
        const hello = sampleClientHello();
        const a = computeJa3(hello);
        const b = computeJa3(hello);
        expect(a).toBe(b);
        expect(a).toMatch(/^[0-9a-f]{32}$/);
    });
});
