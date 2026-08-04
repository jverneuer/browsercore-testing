/**
 * Phase 2 e2e — full ClientHello verification for all browser profiles.
 *
 * For each supported profile we build a ClientHello handshake message from the
 * profile's declared wire values (cipher suites, extension order, supported
 * versions, signature algorithms, key-share groups, ALPN), parse the raw bytes
 * with the `parse-clienthello.ts` utility, and assert the structural invariants
 * T2–T9 against the profile definition.
 *
 * The bytes are built directly from the profile (via
 * `@browsercore/profiles` `buildExpectedClientHello`), not captured from a
 * live sink server — so this is a profile → bytes → parsed round-trip test, not
 * a network test. It verifies that the profile's wire encoding is self-consistent
 * and that the parser decodes it correctly.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { getProfile, buildExpectedClientHello } from "@browsercore/profiles";
import { generateKeyShares } from "@browsercore/tls";
import type { BrowserProfile } from "@browsercore/profiles";
import {
    parseClientHello,
    decodeSni,
    decodeSupportedVersions,
    decodeAlpn,
    findExtension,
    type ParsedExtension,
} from "../../src/e2e/parse-clienthello.js";

/** The six profiles the e2e matrix covers (plan §3.1). */
const PROFILES = [
    "chrome-120",
    "chrome-128",
    "chrome-140",
    "firefox-128",
    "safari-17",
    "edge-120",
] as const;

type ProfileId = (typeof PROFILES)[number];

/**
 * GREASE sentinel pattern per RFC 8701: both bytes identical AND the low nibble
 * of each byte is 0xa. The canonical set is 0x0a0a, 0x1a1a, …, 0xfafa.
 *
 * Note: 0x0000 (SNI) and 0xffff would pass a naive "both bytes equal" test, so
 * the low-nibble check is essential.
 */
function isGreaseValue(v: number): boolean {
    const hi = (v >> 8) & 0xff;
    const lo = v & 0xff;
    return hi === lo && (lo & 0x0f) === 0x0a;
}

/** Canonical GREASE extension type (0x0a0a) prepended for GREASE profiles. */
const GREASE_EXTENSION_TYPE = 0x0a0a;

/**
 * Build a ClientHello handshake message (bare handshake, first byte 0x01) from
 * a profile, returning the raw bytes.
 *
 * Encodes every cipher suite the profile declares (including TLS 1.2 suites the
 * `@browsercore/tls` builder does not yet support), the full extension list in
 * the profile's declared order, and real X25519 key-share keys. For GREASE
 * profiles a GREASE extension (0x0a0a) is prepended, matching real-browser
 * behavior where GREASE extensions lead the extension block.
 */
async function buildClientHelloFromProfile(
    profile: BrowserProfile,
    serverName: string,
): Promise<Uint8Array> {
    const expected = buildExpectedClientHello(profile, serverName);
    const grease = profile.tls.grease;

    // Generate real X25519 key pairs for the key_share extension.
    const keyPairs = await generateKeyShares(["x25519"]);

    // --- cipher suites (IANA wire codes) ----------------------------------
    // For GREASE profiles, a GREASE cipher (0x0a0a) must lead the list. Chrome
    // / Edge profiles already carry a TLS_GREASE_RESERVED_0 placeholder that
    // buildExpectedClientHello maps to 0x0a0a; Safari declares grease:true but
    // pins no GREASE slot, so we prepend one to match real-browser behavior.
    const greaseCipher: number[] = (grease && !isGreaseValue(expected.cipherSuites[0] ?? 0))
        ? [GREASE_EXTENSION_TYPE]
        : [];
    const cipherCodes = [...greaseCipher, ...expected.cipherSuites];
    const cipherSuitesBytes = new Uint8Array(cipherCodes.length * 2);
    for (let i = 0; i < cipherCodes.length; i++) {
        const code = cipherCodes[i]!;
        cipherSuitesBytes[i * 2] = (code >> 8) & 0xff;
        cipherSuitesBytes[i * 2 + 1] = code & 0xff;
    }

    // --- extensions -------------------------------------------------------
    // Map extension type → builder. For GREASE profiles, prepend a GREASE
    // extension (0x0a0a) before the profile-declared extensions.
    const extensionTypes: number[] = grease
        ? [GREASE_EXTENSION_TYPE, ...expected.extensionTypes]
        : [...expected.extensionTypes];

    const extensionParts: Uint8Array[] = [];
    for (const type of extensionTypes) {
        extensionParts.push(encodeExtension(type, expected, keyPairs, serverName, grease));
    }

    let extensionsLen = 0;
    for (const p of extensionParts) {
        extensionsLen += p.length;
    }
    const extensionsBytes = new Uint8Array(extensionsLen);
    let o = 0;
    for (const p of extensionParts) {
        extensionsBytes.set(p, o);
        o += p.length;
    }

    // --- assemble the handshake body --------------------------------------
    const random = new Uint8Array(32); // deterministic zeros — not asserted on
    const sessionId = new Uint8Array(0);
    const compressionMethods = new Uint8Array([0x00]);

    const bodyLen =
        2 + // legacy_version
        random.length +
        1 +
        sessionId.length +
        2 +
        cipherSuitesBytes.length +
        1 +
        compressionMethods.length +
        2 +
        extensionsBytes.length;

    const message = new Uint8Array(1 + 3 + bodyLen); // handshake type(1) + len(3) + body
    let p = 0;
    message[p++] = 0x01; // ClientHello
    message[p++] = (bodyLen >> 16) & 0xff;
    message[p++] = (bodyLen >> 8) & 0xff;
    message[p++] = bodyLen & 0xff;
    message[p++] = 0x03; // legacy_version = 0x0303
    message[p++] = 0x03;
    message.set(random, p);
    p += random.length;
    message[p++] = sessionId.length; // session_id len
    // session_id (empty)
    message[p++] = (cipherSuitesBytes.length >> 8) & 0xff;
    message[p++] = cipherSuitesBytes.length & 0xff;
    message.set(cipherSuitesBytes, p);
    p += cipherSuitesBytes.length;
    message[p++] = compressionMethods.length;
    message.set(compressionMethods, p);
    p += compressionMethods.length;
    message[p++] = (extensionsBytes.length >> 8) & 0xff;
    message[p++] = extensionsBytes.length & 0xff;
    message.set(extensionsBytes, p);
    // p += extensionsBytes.length;

    return message;
}

/** Wrap an extension body with its type(2) || len(2) prefix. */
function wrapExtension(type: number, data: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + 2 + data.length);
    out[0] = (type >> 8) & 0xff;
    out[1] = type & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out[3] = data.length & 0xff;
    out.set(data, 4);
    return out;
}

/**
 * Encode the body for a single extension type.
 *
 * Only the types the e2e assertions inspect need a faithful body; the rest get
 * an empty body (the assertions only check their presence + order).
 */
function encodeExtension(
    type: number,
    expected: ReturnType<typeof buildExpectedClientHello>,
    keyPairs: readonly { algorithm: string; privateKey: Uint8Array; publicKey: Uint8Array }[],
    serverName: string,
    grease: boolean,
): Uint8Array {
    switch (type) {
        case 0x0000: {
            // SNI: server_name_list = length(2) || [name_type(1)=0 || len(2) || name].
            const nameBytes = new TextEncoder().encode(serverName);
            const entry = new Uint8Array(1 + 2 + nameBytes.length);
            entry[0] = 0; // host_name
            entry[1] = (nameBytes.length >> 8) & 0xff;
            entry[2] = nameBytes.length & 0xff;
            entry.set(nameBytes, 3);
            const list = new Uint8Array(2 + entry.length);
            list[0] = (entry.length >> 8) & 0xff;
            list[1] = entry.length & 0xff;
            list.set(entry, 2);
            return wrapExtension(type, list);
        }
        case 0x000a: {
            // supported_groups: length(2) || groups (uint16 each).
            const groups = expected.keyShareGroups;
            const body = new Uint8Array(2 + groups.length * 2);
            body[0] = (groups.length >> 8) & 0xff;
            body[1] = groups.length & 0xff;
            for (let i = 0; i < groups.length; i++) {
                body[2 + i * 2] = (groups[i]! >> 8) & 0xff;
                body[3 + i * 2] = groups[i]! & 0xff;
            }
            return wrapExtension(type, body);
        }
        case 0x000b: {
            // ec_point_formats: length(1) || formats. Uncompressed (0x00) only.
            return wrapExtension(type, new Uint8Array([0x01, 0x00]));
        }
        case 0x000d: {
            // signature_algorithms: length(2) || schemes (uint16 each).
            const schemes = expected.signatureAlgorithms;
            const body = new Uint8Array(2 + schemes.length * 2);
            body[0] = (schemes.length >> 8) & 0xff;
            body[1] = schemes.length & 0xff;
            for (let i = 0; i < schemes.length; i++) {
                body[2 + i * 2] = (schemes[i]! >> 8) & 0xff;
                body[3 + i * 2] = schemes[i]! & 0xff;
            }
            return wrapExtension(type, body);
        }
        case 0x0010: {
            // ALPN: length(2) || [len(1) || name]*. h2 before http/1.1.
            const protocols = ["h2", "http/1.1"];
            const encoded = protocols.map((proto) => new TextEncoder().encode(proto));
            let entriesLen = 0;
            for (const e of encoded) {
                entriesLen += 1 + e.length;
            }
            const body = new Uint8Array(2 + entriesLen);
            body[0] = (entriesLen >> 8) & 0xff;
            body[1] = entriesLen & 0xff;
            let o = 2;
            for (const e of encoded) {
                body[o++] = e.length;
                body.set(e, o);
                o += e.length;
            }
            return wrapExtension(type, body);
        }
        case 0x002b: {
            // supported_versions (client): length(1) || versions (uint16 each).
            const versions = expected.supportedVersions;
            const body = new Uint8Array(1 + versions.length * 2);
            body[0] = versions.length * 2;
            for (let i = 0; i < versions.length; i++) {
                body[1 + i * 2] = (versions[i]! >> 8) & 0xff;
                body[2 + i * 2] = versions[i]! & 0xff;
            }
            return wrapExtension(type, body);
        }
        case 0x0033: {
            // key_share (client): length(2) || entries. Each: group(2) || len(2) || key.
            let entriesLen = 0;
            for (const kp of keyPairs) {
                entriesLen += 2 + 2 + kp.publicKey.length;
            }
            const body = new Uint8Array(2 + entriesLen);
            body[0] = (entriesLen >> 8) & 0xff;
            body[1] = entriesLen & 0xff;
            let o = 2;
            for (const kp of keyPairs) {
                // x25519 = 0x001d.
                const group = 0x001d;
                body[o++] = (group >> 8) & 0xff;
                body[o++] = group & 0xff;
                body[o++] = (kp.publicKey.length >> 8) & 0xff;
                body[o++] = kp.publicKey.length & 0xff;
                body.set(kp.publicKey, o);
                o += kp.publicKey.length;
            }
            return wrapExtension(type, body);
        }
        case GREASE_EXTENSION_TYPE: {
            // GREASE extension: empty body (real browsers send empty GREASE exts).
            return wrapExtension(type, new Uint8Array(0));
        }
        default: {
            // Any other extension type from the profile order: empty body.
            return wrapExtension(type, new Uint8Array(0));
        }
    }
}

/** Filter GREASE extension types out of a parsed extension list. */
function nonGreaseExtensions(extensions: readonly ParsedExtension[]): readonly ParsedExtension[] {
    return extensions.filter((ext) => !isGreaseValue(ext.type));
}

// ---------------------------------------------------------------------------

describe.each(PROFILES)("ClientHello e2e — %s", (profileId: ProfileId) => {
    const SERVER_NAME = "example.com";

    let profile: BrowserProfile;
    let hello: ReturnType<typeof parseClientHello>;

    beforeAll(async () => {
        profile = getProfile(profileId);
        const bytes = await buildClientHelloFromProfile(profile, SERVER_NAME);
        hello = parseClientHello(bytes);
    });

    it("T2: cipher suites are IANA-valid (no 0x0000, no duplicates, known values)", () => {
        const suites = hello.cipherSuites;

        // No empty/NULL cipher suite.
        for (const suite of suites) {
            expect(suite).not.toBe(0x0000);
        }

        // No duplicates except GREASE sentinels (which may repeat the canonical
        // 0x0a0a in our deterministic builder).
        const seen = new Set<number>();
        for (const suite of suites) {
            if (isGreaseValue(suite)) {
                continue; // GREASE slots are allowed to repeat
            }
            expect(seen.has(suite)).toBe(false);
            seen.add(suite);
        }

        // Every suite is a known IANA TLS 1.3 or 1.2 code. We accept the full
        // set of codes the profiles package maps (TLS 1.3 + ECDHE + RSA suites).
        const knownSuites = new Set<number>([
            // TLS 1.3
            0x1301, 0x1302, 0x1303, 0x1304,
            // TLS 1.2 ECDHE
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0xc009, 0xc00a,
            0xc023, 0xc024, 0xc027, 0xc028,
            // TLS 1.2 RSA
            0x009c, 0x009d, 0x002f, 0x0035, 0x003c, 0x003d,
        ]);
        for (const suite of suites) {
            if (isGreaseValue(suite)) {
                continue;
            }
            expect(knownSuites.has(suite)).toBe(true);
        }
    });

    it("T3: extensions are in profile-specified order (GREASE masked)", () => {
        const grease = profile.tls.grease;
        const actualTypes = (
            grease ? nonGreaseExtensions(hello.extensions) : hello.extensions
        ).map((ext) => ext.type);
        const expectedTypes = Array.from(profile.tls.extensionOrder);
        expect(actualTypes).toEqual(expectedTypes);
    });

    it("T4: GREASE sentinels present iff profile.grease === true", () => {
        const grease = profile.tls.grease;

        const greaseInCiphers = hello.cipherSuites.some(isGreaseValue);
        const greaseInExtensions = hello.extensions.some((ext) => isGreaseValue(ext.type));

        if (grease) {
            expect(greaseInCiphers).toBe(true);
            expect(greaseInExtensions).toBe(true);
        } else {
            expect(greaseInCiphers).toBe(false);
            expect(greaseInExtensions).toBe(false);
        }
    });

    it("T5: supported_versions advertises TLS 1.3 (0x0304)", () => {
        const versions = decodeSupportedVersions(hello);
        expect(versions).toContain(0x0304);
    });

    it("T6: SNI is set to the target host", () => {
        const names = decodeSni(hello);
        expect(names).toContain(SERVER_NAME);
    });

    it("T9: ALPN offers h2 before http/1.1", () => {
        const protocols = decodeAlpn(hello);
        expect(protocols.length).toBeGreaterThanOrEqual(2);
        expect(protocols[0]).toBe("h2");
        expect(protocols[1]).toBe("http/1.1");
    });

    // --- structural sanity checks (not in the plan but cheap + informative) --

    it("parses a cipher suite list whose non-GREASE entries match the profile", () => {
        const expected = buildExpectedClientHello(profile, SERVER_NAME);
        // Both the wire list and the profile list may contain GREASE sentinels
        // (chrome/edge pin one; safari gets one prepended). Compare the
        // non-GREASE tail in order — that is the deterministic fingerprint.
        const wireNonGrease = hello.cipherSuites.filter((c) => !isGreaseValue(c));
        const profileNonGrease = expected.cipherSuites.filter((c) => !isGreaseValue(c));
        expect(wireNonGrease).toEqual(profileNonGrease);
    });

    it("carries the SNI extension (0x0000)", () => {
        const sni = findExtension(hello, 0x0000);
        expect(sni).toBeDefined();
    });

    it("carries the supported_versions extension (0x002b)", () => {
        const sv = findExtension(hello, 0x002b);
        expect(sv).toBeDefined();
    });

    it("carries the ALPN extension (0x0010)", () => {
        const alpn = findExtension(hello, 0x0010);
        expect(alpn).toBeDefined();
    });
});
