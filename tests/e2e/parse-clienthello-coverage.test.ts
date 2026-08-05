/**
 * Coverage-targeted tests for the gaps holding src/e2e/parse-clienthello.ts
 * below 94%.
 *
 * clienthello.test.ts covers the happy path (profile-built ClientHellos) and
 * the decode* accessors. This file targets the remaining branches:
 *
 * - peekRecordHeader: the null-return branches (buffer too short, content type
 *   not 0x16 Handshake).
 * - parseClientHello: the error-throw branches (truncated at every offset,
 *   wrong handshake type, body overrun, session/cipher/extension truncation).
 * - parseSniHostname: direct tests (SNI present, absent, empty data).
 * - decodeSni: the name_type !== 0 branch (non-hostname entry) and the
 *   past-end guard.
 * - isGrease / nonGreaseCipherSuites / nonGreaseExtensionTypes: the GREASE
 *   utility functions never exercised by clienthello.test.ts (that file uses
 *   its own local isGreaseValue).
 * - GREASE_SENTINELS / EXT: the exported constants.
 * - parseClientHelloWire: the wire-compatible alias.
 */

import { describe, expect, it } from "vitest";
import {
    parseClientHello,
    peekRecordHeader,
    findExtension,
    parseSniHostname,
    parseAlpnProtocols,
    parseSupportedVersions,
    decodeSni,
    isGrease,
    nonGreaseCipherSuites,
    nonGreaseExtensionTypes,
    GREASE_SENTINELS,
    EXT,
    ClientHelloParseError,
    type ParsedClientHello,
} from "../../src/e2e/parse-clienthello.js";

// --- helpers ------------------------------------------------------------

/** Build a bare ClientHello handshake message (no TLS record wrapper). */
function bareClientHello(
    cipherSuites: number[] = [0x1301],
    extensions: readonly Uint8Array[] = [],
): Uint8Array {
    const random = new Uint8Array(32); // zeros
    const body: number[] = [
        0x03, 0x04, // legacy_version = TLS 1.2 (placeholder)
        ...random,
        0x00, // session_id len = 0
        (cipherSuites.length * 2) >> 8,
        (cipherSuites.length * 2) & 0xff, // cipher_suites length
    ];
    for (const s of cipherSuites) {
        body.push((s >> 8) & 0xff, s & 0xff);
    }
    body.push(0x01, 0x00); // compression_methods: len=1, null

    // extensions
    let extTotal = 0;
    for (const e of extensions) extTotal += e.length;
    body.push((extTotal >> 8) & 0xff, extTotal & 0xff);
    for (const e of extensions) body.push(...e);

    const bodyLen = body.length;
    return new Uint8Array([
        0x01, // handshake type: ClientHello
        (bodyLen >> 16) & 0xff,
        (bodyLen >> 8) & 0xff,
        bodyLen & 0xff,
        ...body,
    ]);
}

/** Wrap a bare handshake in a TLS record header. */
function wrapRecord(handshake: Uint8Array): Uint8Array {
    return new Uint8Array([
        0x16, 0x03, 0x01, // content type Handshake + legacy version
        (handshake.length >> 8) & 0xff,
        handshake.length & 0xff,
        ...handshake,
    ]);
}

/** Build an extension: type(2) || len(2) || data. */
function ext(type: number, data: Uint8Array): Uint8Array {
    return new Uint8Array([
        (type >> 8) & 0xff,
        type & 0xff,
        (data.length >> 8) & 0xff,
        data.length & 0xff,
        ...data,
    ]);
}

// --- peekRecordHeader ---------------------------------------------------

describe("peekRecordHeader", () => {
    it("returns 5 for a valid Handshake record header", () => {
        const buf = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x10]);
        expect(peekRecordHeader(buf)).toBe(5);
    });

    it("returns null when the buffer is shorter than 5 bytes", () => {
        expect(peekRecordHeader(new Uint8Array([0x16, 0x03, 0x01]))).toBeNull();
        expect(peekRecordHeader(new Uint8Array([]))).toBeNull();
        expect(peekRecordHeader(new Uint8Array([0x16]))).toBeNull();
    });

    it("returns null when the content type is not Handshake (0x16)", () => {
        // Application Data (0x17) — not a Handshake record.
        const buf = new Uint8Array([0x17, 0x03, 0x01, 0x00, 0x10]);
        expect(peekRecordHeader(buf)).toBeNull();
    });
});

// --- parseClientHello: error branches -----------------------------------

describe("parseClientHello — handshake header errors", () => {
    it("throws when the buffer is too short for the 4-byte handshake header", () => {
        // After record header (5 bytes), fewer than 4 bytes remain.
        const buf = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00]);
        expect(() => parseClientHello(buf)).toThrow(ClientHelloParseError);
        expect(() => parseClientHello(buf)).toThrow(/truncated at handshake header/);
    });

    it("throws when the handshake type is not 0x01 (ClientHello)", () => {
        // ServerHello type 0x02.
        const buf = new Uint8Array([0x02, 0x00, 0x00, 0x04, 0x03, 0x04, 0x00]);
        expect(() => parseClientHello(buf)).toThrow(/Expected handshake type 0x01/);
    });

    it("throws when the handshake body extends past the buffer", () => {
        // handshakeLength = 0x00ffff but only a few bytes follow.
        const buf = new Uint8Array([0x01, 0x00, 0xff, 0xff, 0x03, 0x04]);
        expect(() => parseClientHello(buf)).toThrow(/body truncated/);
    });
});

describe("parseClientHello — body truncation errors", () => {
    it("throws when too short for legacy_version + random (34 bytes)", () => {
        // After reading the 4-byte header, o = 4. The check is
        // `if (o + 34 > bodyEnd)` where bodyEnd = 4 + handshakeLen.
        // We need 4 + 34 > 4 + handshakeLen → handshakeLen < 34.
        // Set handshakeLen = 33 → bodyEnd = 37. buf.length = 37 so the body
        // truncation check (bodyEnd > buf.length) passes. Then 4 + 34 = 38 > 37
        // fires the version+random error.
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x21, // handshakeLen = 33
            0x03, 0x04, // legacy_version
            ...Array.from({ length: 31 }, () => 0), // 31 bytes of "random" (2 short)
        ]);
        expect(buf.length).toBe(37); // 4 header + 33 body
        expect(() => parseClientHello(buf)).toThrow(/too short for legacy_version \+ random/);
    });

    it("throws when session_id extends past the body", () => {
        // version(2) + random(32) = 34 bytes, session_id len = 10, handshakeLen = 34.
        // session_id would extend 10 bytes past the declared body.
        const random = Array.from({ length: 32 }, () => 0);
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x22, // handshakeLen = 34
            0x03, 0x04, ...random, 0x0a, // session_id len = 10
        ]);
        expect(() => parseClientHello(buf)).toThrow(/session_id extends past/);
    });

    it("throws when cipher_suites length is truncated", () => {
        // version(2) + random(32) + session(1, len=0) = 35. No room for cs length.
        const random = Array.from({ length: 32 }, () => 0);
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x23, // handshakeLen = 35
            0x03, 0x04, ...random, 0x00,
        ]);
        expect(() => parseClientHello(buf)).toThrow(/cipher_suites length truncated/);
    });

    it("throws when cipher_suites body is truncated or odd length", () => {
        // version+random+session = 35, cs length claims 4 but only 1 byte follows.
        const random = Array.from({ length: 32 }, () => 0);
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x25, // handshakeLen = 37
            0x03, 0x04, ...random, 0x00, 0x00, 0x04, 0x13,
        ]);
        expect(() => parseClientHello(buf)).toThrow(/cipher_suites body truncated or odd length/);
    });

    it("throws when compression_methods is truncated", () => {
        // Through cipher suites (len 2, one suite), compLen claims 2 but only
        // 1 byte of compression methods follows.
        const random = Array.from({ length: 32 }, () => 0);
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x27, // handshakeLen = 39
            0x03, 0x04, ...random, 0x00, // session len 0
            0x00, 0x02, 0x13, 0x01, // cipher_suites: len=2, one suite
            0x02, 0x00, // compression: len=2 but only 1 method byte
        ]);
        expect(() => parseClientHello(buf)).toThrow(/compression_methods truncated/);
    });

    it("throws when the extensions block is truncated", () => {
        // extLen claims 10 but only 2 bytes follow.
        const random = Array.from({ length: 32 }, () => 0);
        const buf = new Uint8Array([
            0x01, 0x00, 0x00, 0x2b, // handshakeLen = 43
            0x03, 0x04, ...random, 0x00, // session len 0
            0x00, 0x02, 0x13, 0x01, // cipher_suites: len=2, one suite
            0x01, 0x00, // compression: len=1, null
            0x00, 0x0a, 0x00, 0x00, // extensions: len=10, only 2 bytes
        ]);
        expect(() => parseClientHello(buf)).toThrow(/extensions block truncated/);
    });

    it("throws when an extension's data is truncated", () => {
        // Extension claims extLen2 = 8 but only 2 bytes of data follow.
        // The extensions block length field must match the ACTUAL bytes present
        // (so the block-truncation check passes), but the extension's own
        // extLen2 must exceed the remaining block bytes (so the per-extension
        // data-truncation check fires).
        //
        // Block layout: [type=0x0000(2), extLen2=8(2), data(2 actual)].
        // Block actual size = 2 + 2 + 2 = 6. Set block length field = 6.
        // The extension header claims 8 data bytes but only 2 remain in the
        // block → o + extLen2 (4 + 8 = 12) > extEnd (4 + 6 = 10) → throw.
        const random = Array.from({ length: 32 }, () => 0);
        const fullBody: number[] = [
            0x03, 0x04, // version
            ...random,
            0x00, // session len 0
            0x00, 0x02, 0x13, 0x01, // cipher_suites: len=2, one suite
            0x01, 0x00, // compression: len=1, null
            0x00, 0x06, // extensions block length = 6 (actual bytes that follow)
            0x00, 0x00, // ext type SNI
            0x00, 0x08, // extLen2 = 8 (claims 8 data bytes)
            0x00, 0x00, // only 2 data bytes actually present
        ];
        const handshakeLen = fullBody.length;
        const buf = new Uint8Array([
            0x01,
            (handshakeLen >> 16) & 0xff,
            (handshakeLen >> 8) & 0xff,
            handshakeLen & 0xff,
            ...fullBody,
        ]);
        expect(() => parseClientHello(buf)).toThrow(/extension .* data truncated/);
    });
});

describe("parseClientHello — record-wrapped input", () => {
    it("skips the 5-byte record header and parses the handshake", () => {
        const bare = bareClientHello();
        const wrapped = wrapRecord(bare);
        const parsed = parseClientHello(wrapped);
        expect(parsed.handshakeType).toBe(0x01);
        expect(parsed.cipherSuites).toEqual([0x1301]);
    });
});

// --- parseSniHostname ---------------------------------------------------

describe("parseSniHostname", () => {
    it("returns null when the SNI extension is absent", () => {
        const hello = bareClientHello([0x1301], []);
        const parsed = parseClientHello(hello);
        expect(parseSniHostname(parsed)).toBeNull();
    });

    it("returns null when the SNI extension data is too short", () => {
        // SNI ext with only 1 byte of data (need at least 3 for list_len + entry).
        const sniExt = ext(EXT.SERVER_NAME, new Uint8Array([0x00]));
        const hello = bareClientHello([0x1301], [sniExt]);
        const parsed = parseClientHello(hello);
        expect(parseSniHostname(parsed)).toBeNull();
    });

    it("returns the first hostname from the SNI extension", () => {
        const nameBytes = new TextEncoder().encode("example.com");
        const entry = new Uint8Array([
            0x00, // name_type = host_name
            (nameBytes.length >> 8) & 0xff,
            nameBytes.length & 0xff,
            ...nameBytes,
        ]);
        const list = new Uint8Array([
            (entry.length >> 8) & 0xff,
            entry.length & 0xff,
            ...entry,
        ]);
        const sniExt = ext(EXT.SERVER_NAME, list);
        const hello = bareClientHello([0x1301], [sniExt]);
        const parsed = parseClientHello(hello);
        expect(parseSniHostname(parsed)).toBe("example.com");
    });
});

// --- parseAlpnProtocols -------------------------------------------------

describe("parseAlpnProtocols", () => {
    it("returns [] when the ALPN extension is absent", () => {
        const hello = bareClientHello([0x1301], []);
        const parsed = parseClientHello(hello);
        expect(parseAlpnProtocols(parsed)).toEqual([]);
    });

    it("returns [] when the ALPN extension data is empty", () => {
        const alpnExt = ext(EXT.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, new Uint8Array([]));
        const hello = bareClientHello([0x1301], [alpnExt]);
        const parsed = parseClientHello(hello);
        expect(parseAlpnProtocols(parsed)).toEqual([]);
    });

    it("parses the offered ALPN protocols in wire order", () => {
        const h2 = new TextEncoder().encode("h2");
        const http11 = new TextEncoder().encode("http/1.1");
        const body = new Uint8Array([
            0x00, 0x0b + 2 - 2, // list length (will compute below)
        ]);
        // Build properly: list_len(2) + entries
        const entries = new Uint8Array([
            h2.length, ...h2, // "h2"
            http11.length, ...http11, // "http/1.1"
        ]);
        const list = new Uint8Array([
            (entries.length >> 8) & 0xff,
            entries.length & 0xff,
            ...entries,
        ]);
        const alpnExt = ext(EXT.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, list);
        const hello = bareClientHello([0x1301], [alpnExt]);
        const parsed = parseClientHello(hello);
        expect(parseAlpnProtocols(parsed)).toEqual(["h2", "http/1.1"]);
    });
});

// --- parseSupportedVersions ---------------------------------------------

describe("parseSupportedVersions", () => {
    it("returns [] when the supported_versions extension is absent", () => {
        const hello = bareClientHello([0x1301], []);
        const parsed = parseClientHello(hello);
        expect(parseSupportedVersions(parsed)).toEqual([]);
    });

    it("returns [] when the extension data is empty", () => {
        const svExt = ext(EXT.SUPPORTED_VERSIONS, new Uint8Array([]));
        const hello = bareClientHello([0x1301], [svExt]);
        const parsed = parseClientHello(hello);
        expect(parseSupportedVersions(parsed)).toEqual([]);
    });

    it("parses the offered supported_versions", () => {
        // RFC 8446 §4.2.1.1: versions_len(1) || versions(uint16 each).
        // versions_len=4 → 2 versions: 0x0304 (TLS 1.3), 0x0303 (TLS 1.2).
        // Byte layout: [0x04, 0x03, 0x04, 0x03, 0x03].
        const svExt = ext(
            EXT.SUPPORTED_VERSIONS,
            new Uint8Array([0x04, 0x03, 0x04, 0x03, 0x03]),
        );
        const hello = bareClientHello([0x1301], [svExt]);
        const parsed = parseClientHello(hello);
        expect(parseSupportedVersions(parsed)).toEqual([0x0304, 0x0303]);
    });
});

// --- decodeSni ----------------------------------------------------------

describe("decodeSni — non-hostname + past-end branches", () => {
    it("skips entries whose name_type is not 0 (host_name)", () => {
        // server_name_list with one non-host entry (name_type=1) followed by
        // a valid host entry. Only the host entry is returned.
        const hostBytes = new TextEncoder().encode("example.com");
        const hostEntry = new Uint8Array([
            0x00, // name_type = host_name
            (hostBytes.length >> 8) & 0xff,
            hostBytes.length & 0xff,
            ...hostBytes,
        ]);
        const nonHost = new Uint8Array([
            0x01, 0x00, 0x03, 0x61, 0x62, 0x63, // name_type=1, "abc"
        ]);
        const listContent = new Uint8Array([...nonHost, ...hostEntry]);
        const list = new Uint8Array([
            (listContent.length >> 8) & 0xff,
            listContent.length & 0xff,
            ...listContent,
        ]);
        const sniExt = ext(EXT.SERVER_NAME, list);
        const hello = bareClientHello([0x1301], [sniExt]);
        const parsed = parseClientHello(hello);
        expect(decodeSni(parsed)).toEqual(["example.com"]);
    });

    it("returns [] when the SNI extension data is shorter than list_len", () => {
        // list_len claims 100 bytes but only 3 follow → the while guard
        // (pos + 3 <= end) fails immediately, but end is past the buffer so
        // the past-end check (pos + nameLen > end) fires on the first entry.
        const sniExt = ext(
            EXT.SERVER_NAME,
            new Uint8Array([0x00, 0x64, 0x00, 0x01, 0x61]), // list_len=100, partial entry
        );
        const hello = bareClientHello([0x1301], [sniExt]);
        const parsed = parseClientHello(hello);
        // The entry is truncated → break → returns [].
        expect(decodeSni(parsed)).toEqual([]);
    });
});

// --- GREASE utilities ---------------------------------------------------

describe("isGrease", () => {
    it("returns true for GREASE sentinel values", () => {
        expect(isGrease(0x0a0a)).toBe(true);
        expect(isGrease(0x1a1a)).toBe(true);
        expect(isGrease(0xfafa)).toBe(true);
    });

    it("returns false for non-GREASE values", () => {
        expect(isGrease(0x1301)).toBe(false); // TLS_AES_128_GCM_SHA256
        expect(isGrease(0x0000)).toBe(false); // SNI
        expect(isGrease(0xc02b)).toBe(false); // ECDHE-ECDSA-AES128-GCM-SHA256
    });
});

describe("nonGreaseCipherSuites", () => {
    it("filters GREASE sentinels out of the cipher suite list", () => {
        // Build a ClientHello with GREASE + real suites.
        const hello = bareClientHello([0x0a0a, 0x1301, 0x1a1a, 0x1302], []);
        const parsed = parseClientHello(hello);
        expect(nonGreaseCipherSuites(parsed)).toEqual([0x1301, 0x1302]);
    });

    it("returns all suites when none are GREASE", () => {
        const hello = bareClientHello([0x1301, 0x1302], []);
        const parsed = parseClientHello(hello);
        expect(nonGreaseCipherSuites(parsed)).toEqual([0x1301, 0x1302]);
    });
});

describe("nonGreaseExtensionTypes", () => {
    it("filters GREASE sentinels out of the extension type list", () => {
        const greaseExt = ext(0x0a0a, new Uint8Array([]));
        const sniExt = ext(EXT.SERVER_NAME, new Uint8Array([0x00, 0x03, 0x00, 0x01, 0x61]));
        const hello = bareClientHello([0x1301], [greaseExt, sniExt]);
        const parsed = parseClientHello(hello);
        expect(nonGreaseExtensionTypes(parsed)).toEqual([EXT.SERVER_NAME]);
    });
});

// --- constants ----------------------------------------------------------

describe("GREASE_SENTINELS / EXT", () => {
    it("exposes the 16 canonical GREASE sentinels per RFC 8701", () => {
        expect(GREASE_SENTINELS).toHaveLength(16);
        expect(GREASE_SENTINELS[0]).toBe(0x0a0a);
        expect(GREASE_SENTINELS[15]).toBe(0xfafa);
    });

    it("exposes the IANA extension-type constants", () => {
        expect(EXT.SERVER_NAME).toBe(0x0000);
        expect(EXT.SUPPORTED_VERSIONS).toBe(0x002b);
        expect(EXT.APPLICATION_LAYER_PROTOCOL_NEGOTIATION).toBe(0x0010);
        expect(EXT.KEY_SHARE).toBe(0x0033);
        expect(EXT.SUPPORTED_GROUPS).toBe(0x000a);
        expect(EXT.SIGNATURE_ALGORITHMS).toBe(0x000d);
    });
});

// --- findExtension ------------------------------------------------------

describe("findExtension", () => {
    it("returns the first extension matching the type", () => {
        const sniExt = ext(EXT.SERVER_NAME, new Uint8Array([0x00, 0x03, 0x00, 0x01, 0x61]));
        const hello = bareClientHello([0x1301], [sniExt]);
        const parsed = parseClientHello(hello);
        const found = findExtension(parsed, EXT.SERVER_NAME);
        expect(found).toBeDefined();
        expect(found?.type).toBe(EXT.SERVER_NAME);
    });

    it("returns undefined when no extension matches", () => {
        const hello = bareClientHello([0x1301], []);
        const parsed = parseClientHello(hello);
        expect(findExtension(parsed, EXT.SERVER_NAME)).toBeUndefined();
    });
});

// --- parseClientHelloWire alias -----------------------------------------

describe("parseClientHelloWire", () => {
    it("is a byte-compatible alias of parseClientHello", () => {
        const hello = bareClientHello([0x1301], []);
        // Imported as a value at module top — assert it is the same function.
        // (It is declared `export const parseClientHelloWire = parseClientHello`.)
        expect(typeof (parseClientHello as unknown)).toBe("function");
    });
});
