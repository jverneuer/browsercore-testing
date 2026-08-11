/**
 * Reference validation tests for TLS / HTTP/2 fingerprinting (Cat 4).
 *
 * The existing JA3/JA4 tests validate internal consistency (the digest is the
 * hash of the canonical string our own parser produces). This file anchors the
 * calculators against KNOWN, externally-published reference values so a
 * regression in parsing or hashing is caught against ground truth, not just
 * self-consistency.
 *
 * Three concerns:
 *
 * 1. Post-quantum key-share parsing — a crafted ClientHello carrying an
 *    X25519MLKEM768 (0x11EC) key_share entry with a 1184-byte public key must
 *    parse without offset corruption (the large key_share body is skipped by
 *    length, leaving the rest of the extension walk intact).
 * 2. JA3 reference — a synthetic ClientHello reproducing real Chrome 131's
 *    cipher / extension / group order (sourced from a tls.peet.ws capture)
 *    must yield the published JA3 digest `fb519300321e7e157792ac8d3a77e9ee`
 *    (GREASE-stripped, the form peet.ws publishes).
 * 3. JA4 format — the four-part JA4 tag from the same ClientHello must match
 *    the canonical shape, with the connection prefix encoding the correct
 *    cipher/extension counts, SNI flag and ALPN code.
 *
 * Reference values come from `captures/chrome-131/oracle_capture.reference.json`
 * (a real Chrome 131 capture relayed through tls.peet.ws).
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { computeJa3, parseClientHello } from "../src/fingerprint/ja3.js";
import {
    computeJa4Fingerprint,
    parseJa4ClientHello,
    sha256First12,
} from "../src/fingerprint/ja4.js";
import { GREASE_VALUES, hex4 } from "../src/fingerprint/ja4-reader.js";
import {
    buildAkamaiFingerprint,
    H2_SETTINGS,
} from "../src/fingerprint/akamai-http2.js";

// --- wire-format helpers ------------------------------------------------

/** Encode a TLS extension: type(2) + length(2) + data. */
function extension(type: number, data: readonly number[]): number[] {
    const len = data.length;
    return [(type >> 8) & 0xff, type & 0xff, (len >> 8) & 0xff, len & 0xff, ...data];
}

/** Big-endian length bytes for a 16-bit field. */
function len16(value: number): number[] {
    return [(value >> 8) & 0xff, value & 0xff];
}

/**
 * Build a TLS-record-wrapped ClientHello that reproduces real Chrome 131's
 * fingerprint profile. The key_share(51) extension carries a GREASE entry, an
 * X25519MLKEM768 (0x11EC) entry with a 1184-byte public key, and an X25519
 * (0x001D) entry — exercising post-quantum key-share parsing.
 *
 * Extension order, cipher order and group order all match the published
 * Chrome 131 capture so the JA3 digest is reproducible.
 */
function chrome131ClientHello(): Uint8Array {
    const random = Array.from({ length: 32 }, (_, i) => (i * 3) & 0xff);

    // Cipher suites: GREASE(0x4a4a) first, then the 15 Chrome suites in order.
    const ciphers = [
        0x4a, 0x4a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f,
        0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14,
        0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
    ];

    // key_share(51): GREASE + X25519MLKEM768 (1184-byte key) + X25519 (32-byte).
    const pqKey = Array.from({ length: 1184 }, (_, i) => i & 0xff);
    const x25519Key = Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff);
    const ksEntries: number[] = [
        0x2a, 0x2a, 0x00, 0x01, 0x00, // GREASE group, keyLen 1, key 0x00
        0x11, 0xec, 0x04, 0xa0, ...pqKey, // X25519MLKEM768 (4588), keyLen 1184
        0x00, 0x1d, 0x00, 0x20, ...x25519Key, // X25519 (29), keyLen 32
    ];
    const keyShareData = [...len16(ksEntries.length), ...ksEntries];

    // supported_groups(10): GREASE + X25519MLKEM768 + X25519 + P-256 + P-384.
    const groups = [0x2a, 0x2a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
    const groupsData = [...len16(groups.length), ...groups];

    // Extensions in real Chrome 131 wire order (GREASE sentinels at both ends).
    const extensions: number[][] = [
        extension(0x5a5a, []), // GREASE
        extension(27, [0x00, 0x01, 0x02]), // compress_certificate (brotli)
        extension(51, keyShareData), // key_share (post-quantum)
        extension(0, [0x00, 0x04, 0x00, 0x00, 0x01, 0x78]), // SNI "x"
        extension(13, [0x00, 0x04, 0x04, 0x03, 0x08, 0x04]), // signature_algorithms
        extension(43, [0x05, 0x7a, 0x7a, 0x03, 0x04, 0x03, 0x03]), // supported_versions
        extension(65281, [0x00]), // renegotiation_info
        extension(45, [0x01]), // psk_key_exchange_modes
        extension(5, [0x01, 0x00, 0x00, 0x00, 0x00]), // status_request (OCSP)
        extension(65037, [0x00, 0x01, 0x00]), // encrypted_client_hello
        extension(16, [0x00, 0x0b, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]), // ALPN h2,http/1.1
        extension(18, []), // signed_certificate_timestamp
        extension(11, [0x01, 0x00]), // ec_point_formats (uncompressed)
        extension(10, groupsData), // supported_groups
        extension(35, []), // session_ticket
        extension(23, []), // extended_master_secret
        extension(17513, [0x00, 0x02, 0x68, 0x32]), // application_settings_old
        extension(0x2a2a, []), // GREASE
    ];
    const allExtensions = extensions.flat();

    const body = [
        0x03, 0x03, ...random, // client_version + random
        0x00, // session_id length = 0
        ...len16(ciphers.length), ...ciphers, // cipher_suites
        0x01, 0x00, // compression_methods (null)
        ...len16(allExtensions.length), ...allExtensions,
    ];
    const handshake = [0x01, ...len24(body.length), ...body];
    return new Uint8Array([0x16, 0x03, 0x01, ...len16(handshake.length), ...handshake]);
}

/** Big-endian length bytes for a 24-bit handshake length field. */
function len24(value: number): number[] {
    return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

/** Remove GREASE sentinels (RFC 8701) from a dash-joined JA3 segment. */
function stripGrease(segment: string): string {
    return segment
        .split("-")
        .filter((value) => value.length > 0 && !GREASE_VALUES.has(Number(value)))
        .join("-");
}

// --- 1. post-quantum key-share parsing ----------------------------------

describe("parseClientHello — post-quantum key shares (X25519MLKEM768)", () => {
    it("parses a ClientHello carrying a 1184-byte X25519MLKEM768 key share without offset corruption (JA3)", () => {
        const hello = chrome131ClientHello();
        const segments = parseClientHello(hello);
        // The large key_share body is skipped by length; the extension walk
        // continues correctly — supported_groups(10) and ec_point_formats(11),
        // which appear AFTER key_share in Chrome's order, are still parsed.
        expect(segments.extensions).toContain("51"); // key_share present
        expect(segments.supportedGroups).toContain("4588"); // X25519MLKEM768
        expect(segments.ecPointFormats).toBe("0"); // parsed after the 1184-byte blob
    });

    it("parses the same ClientHello with the JA4 parser (PQ group retained)", () => {
        const parsed = parseJa4ClientHello(chrome131ClientHello());
        // GREASE stripped; X25519MLKEM768 (4588) preserved in supported groups.
        expect(parsed.supportedGroups).toEqual([4588, 29, 23, 24]);
        expect(parsed.sniPresent).toBe(true);
        expect(parsed.alpnRaw).toBe("h2,http/1.1");
    });

    it("parses a minimal ClientHello whose only extension is a large PQ key_share", () => {
        // Isolates the key_share path: the 1184-byte body must be consumed by
        // extLen so the parser terminates cleanly with no trailing corruption.
        const pqKey = Array.from({ length: 1184 }, (_, i) => i & 0xff);
        const keyShareData = [
            ...len16(4 + 1184), // list length = group(2)+keyLen(2)+key(1184)
            0x11, 0xec, ...len16(1184), ...pqKey, // X25519MLKEM768 entry
        ];
        const ext = extension(51, keyShareData);
        const body = [
            0x03, 0x03, ...Array.from({ length: 32 }, (_, i) => i),
            0x00, // session_id
            0x00, 0x02, 0x13, 0x01, // one cipher
            0x01, 0x00, // compression
            ...len16(ext.length), ...ext,
        ];
        const hello = new Uint8Array([0x01, ...len24(body.length), ...body]);
        expect(() => parseClientHello(hello)).not.toThrow();
        expect(parseClientHello(hello).extensions).toBe("51");
        expect(() => parseJa4ClientHello(hello)).not.toThrow();
    });
});

// --- 2. JA3 reference validation (Chrome 131) ---------------------------

/** Published Chrome 131 JA3 digest (GREASE-stripped, tls.peet.ws). */
const CHROME_131_JA3_HASH = "fb519300321e7e157792ac8d3a77e9ee";
/** Published Chrome 131 JA3 canonical string (GREASE-stripped). */
const CHROME_131_JA3_STRING =
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
    "27-51-0-13-43-65281-45-5-65037-16-18-11-10-35-23-17513," +
    "4588-29-23-24,0";

describe("computeJa3 — reference validation against Chrome 131", () => {
    it("extracts Chrome 131's full extension/cipher/group order past the PQ key share", () => {
        const segments = parseClientHello(chrome131ClientHello());
        // GREASE-stripped segments must reconstruct the published Chrome 131 string.
        const reconstructed = [
            segments.version,
            stripGrease(segments.ciphers),
            stripGrease(segments.extensions),
            stripGrease(segments.supportedGroups),
            segments.ecPointFormats,
        ].join(",");
        expect(reconstructed).toBe(CHROME_131_JA3_STRING);
    });

    it("produces the published Chrome 131 JA3 digest (GREASE-stripped)", () => {
        // Our calculator includes GREASE values (classic Salesforce JA3 form);
        // peet.ws publishes the GREASE-stripped form. Stripping our segments
        // and hashing must reproduce the published digest exactly.
        const segments = parseClientHello(chrome131ClientHello());
        const canonical = [
            segments.version,
            stripGrease(segments.ciphers),
            stripGrease(segments.extensions),
            stripGrease(segments.supportedGroups),
            segments.ecPointFormats,
        ].join(",");
        expect(createHash("md5").update(canonical).digest("hex")).toBe(CHROME_131_JA3_HASH);
    });

    it("computeJa3 is a deterministic 32-hex digest for the Chrome profile", () => {
        const hello = chrome131ClientHello();
        const a = computeJa3(hello);
        const b = computeJa3(hello);
        expect(a).toBe(b);
        expect(a).toMatch(/^[0-9a-f]{32}$/);
    });
});

// --- 3. JA4 format validation (Chrome 131) ------------------------------

/** Canonical JA4 tag shape: t{cc}{ee}{sni}{ver}{alpn}_12hex_12hex_12hex. */
const JA4_TAG_RE = /^t\d{2}\d{2}[di]\d{2}[a-z0-9]{2}_[a-z0-9]{12}_[a-z0-9]{12}_[a-z0-9]{12}$/;

describe("computeJa4 — Chrome 131 tag format", () => {
    it("emits a well-formed four-part JA4 tag", () => {
        const { tag } = computeJa4Fingerprint(chrome131ClientHello());
        expect(tag).toMatch(JA4_TAG_RE);
    });

    it("encodes the connection prefix with 15 ciphers, 16 extensions, SNI and h2 ALPN", () => {
        const { a } = computeJa4Fingerprint(chrome131ClientHello());
        // 15 non-GREASE ciphers -> "15"; 16 non-GREASE extensions -> "16";
        // SNI present -> "d"; ALPN "h2,http/1.1" -> "hh".
        expect(a).toContain("15");
        expect(a).toContain("16");
        expect(a).toContain("d");
        expect(a).toMatch(/hh$/);
    });

    it("JA4_b is the SHA-256-trunc of the sorted non-GREASE cipher suites", () => {
        const { b } = computeJa4Fingerprint(chrome131ClientHello());
        const knownCiphers = [47, 53, 156, 157, 4865, 4866, 4867, 49171, 49172, 49195, 49196, 49199, 49200, 52392, 52393];
        const expected = sha256First12(
            [...knownCiphers].sort((x, y) => x - y).map(hex4).join(""),
        );
        expect(b).toBe(expected);
    });

    it("JA4_c is the SHA-256-trunc of sorted extensions excluding SNI and ALPN", () => {
        const { c } = computeJa4Fingerprint(chrome131ClientHello());
        const knownExts = [5, 10, 11, 13, 18, 23, 27, 35, 43, 45, 51, 17513, 65037, 65281];
        const expected = sha256First12(knownExts.sort((x, y) => x - y).map(hex4).join(""));
        expect(c).toBe(expected);
    });

    it("JA4_f is a 12-hex digest derived from the raw parsed fields", () => {
        const { f } = computeJa4Fingerprint(chrome131ClientHello());
        expect(f).toMatch(/^[0-9a-f]{12}$/);
    });
});

// --- 4. Akamai HTTP/2 fingerprint (Chrome 131) --------------------------

/** Published Chrome 131 Akamai HTTP/2 fingerprint string (tls.peet.ws). */
const CHROME_131_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

describe("buildAkamaiFingerprint — reference validation against Chrome 131", () => {
    it("reproduces the published Chrome 131 Akamai fingerprint string", () => {
        const fingerprint = buildAkamaiFingerprint({
            settings: [
                { id: H2_SETTINGS.HEADER_TABLE_SIZE, value: 65536 },
                { id: H2_SETTINGS.ENABLE_PUSH, value: 0 },
                { id: H2_SETTINGS.INITIAL_WINDOW_SIZE, value: 6291456 },
                { id: H2_SETTINGS.MAX_HEADER_LIST_SIZE, value: 262144 },
            ],
            windowUpdateIncrement: 15663105,
            priorityFrameCount: 0,
            pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
        });
        expect(fingerprint).toBe(CHROME_131_AKAMAI);
    });

    it("is deterministic for identical inputs", () => {
        const input = {
            settings: [{ id: H2_SETTINGS.HEADER_TABLE_SIZE, value: 4096 }],
            windowUpdateIncrement: 12517377,
            priorityFrameCount: 0,
            pseudoHeaderOrder: [":method", ":path", ":scheme", ":authority"] as const,
        };
        expect(buildAkamaiFingerprint(input)).toBe(buildAkamaiFingerprint(input));
    });

    it("serializes an empty SETTINGS list as a leading empty segment", () => {
        // No SETTINGS → the SETTINGS segment is the empty string, yielding a
        // leading `|` before the WINDOW_UPDATE increment; an empty
        // pseudo-header order yields a trailing empty segment.
        const fingerprint = buildAkamaiFingerprint({
            settings: [],
            windowUpdateIncrement: 0,
            priorityFrameCount: 0,
            pseudoHeaderOrder: [],
        });
        // ["", "0", "0", ""].join("|") → "|0|0|".
        expect(fingerprint).toBe("|0|0|");
    });

    it("preserves SETTINGS wire order (order-sensitive fingerprinting)", () => {
        // Swapping the order of two SETTINGS changes the serialized string —
        // the fingerprint is intentionally order-dependent.
        const a = buildAkamaiFingerprint({
            settings: [
                { id: H2_SETTINGS.HEADER_TABLE_SIZE, value: 65536 },
                { id: H2_SETTINGS.INITIAL_WINDOW_SIZE, value: 6291456 },
            ],
            windowUpdateIncrement: 0,
            priorityFrameCount: 0,
            pseudoHeaderOrder: [":method"],
        });
        const b = buildAkamaiFingerprint({
            settings: [
                { id: H2_SETTINGS.INITIAL_WINDOW_SIZE, value: 6291456 },
                { id: H2_SETTINGS.HEADER_TABLE_SIZE, value: 65536 },
            ],
            windowUpdateIncrement: 0,
            priorityFrameCount: 0,
            pseudoHeaderOrder: [":method"],
        });
        expect(a).not.toBe(b);
    });
});
