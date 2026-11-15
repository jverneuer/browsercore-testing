/**
 * REAL ClientHello emission test — the opening TLS record of the REAL stack.
 *
 * Companion to emission-h2-prelude.test.ts (0.2.9): goldens that only
 * self-compare catch nothing. This file drives the REAL `@browsercore/tls`
 * 0.4.14 handshake (`connectTls` → `runHandshake` → the production
 * `buildClientHello` + record-layer write path) over a fake transport, with
 * the chrome-140 profile from `@browsercore/profiles` 0.2.4 and a
 * deterministic random source so the six RFC 8701 GREASE sentinels are stable,
 * and asserts the emitted structure against ORACLE ground truth:
 *
 *   - captures/chrome-131/tls/client_hello.bin — the golden real capture:
 *     opens with record version bytes `16 03 01` (legacy TLS 1.0 version on
 *     the initial ClientHello record, RFC 8446 §5.1), key_share opens with a
 *     GREASE entry carrying a 1-byte 0x00 payload (`caca 0001 00`) followed by
 *     X25519MLKEM768 (1216B) and x25519 (32B), supported_groups lists
 *     GREASE|4588|29|23|24, and the ClientHello terminates with a GREASE
 *     extension whose body is a single 0x00 byte.
 *   - captures/chrome-131/oracle_capture.reference.json — tls section: ALPS
 *     carries an h2-only body, supported_versions leads with GREASE.
 *
 * The chrome-140 profile (profiles 0.2.4) splits keyShareGroups
 * (X25519MLKEM768+x25519, what key_share CARRIES) from
 * keyShareAdvertisedGroups (+secp256r1+secp384r1, what supported_groups
 * ADVERTISES) — tls 0.4.14 consumes that split via
 * ClientHelloConfig.supportedGroups. (Finding: @browsercore/fetch 0.2.17 does
 * not forward the split yet, so this browser-correct emission is only
 * observable driving tls directly.)
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { connectTls, GREASE_VALUES, isGreaseValue, TLS_1_2, TLS_1_3 } from "@browsercore/tls";
import type { ClientHelloConfig } from "@browsercore/tls";
import type { CryptoProvider } from "@browsercore/crypto";
import { DeterministicRandom } from "@browsercore/transport";
import { getProfile } from "@browsercore/profiles";
import type { ProfileId } from "@browsercore/profiles";
import { parseClientHello } from "../../src/e2e/parse-clienthello.js";
import type { ParsedClientHello, ParsedExtension } from "../../src/e2e/parse-clienthello.js";
import { nodeCryptoProvider } from "../../src/reference/node-crypto-provider.js";
import { CaptureTransport, captureEventProvider } from "./emission-fakes.js";

const SERVER_NAME = "tls.peet.ws";

/**
 * Deterministic xorshift32 seed for GREASE draws. With this seed the six
 * per-slot sentinels emitted on the wire are 0x8a8a (cipher), 0xbaba (leading
 * ext), 0xaaaa (key_share), 0xeaea (supported_groups), 0x5a5a
 * (supported_versions), 0x9a9a (trailing ext) — pairwise distinct, matching
 * how real Chrome's independent draws landed in the golden chrome-131 capture
 * (cipher 0x5a5a, ext 0x4a4a, groups 0xcaca — no slot reuse).
 */
const GREASE_SEED = 0x5eed1234;

/** One key_share entry as it appears on the wire (RFC 8446 §4.2.8). */
interface KeyShareEntry {
    readonly group: number;
    readonly keyLength: number;
    readonly keyBytes: Uint8Array;
}

/** Decode the key_share extension body into its ordered entries. */
function decodeKeyShareEntries(ext: ParsedExtension): KeyShareEntry[] {
    const data = ext.data;
    const listLength = (data[0]! << 8) | data[1]!;
    const entries: KeyShareEntry[] = [];
    let offset = 2;
    while (offset < 2 + listLength) {
        const group = (data[offset]! << 8) | data[offset + 1]!;
        const keyLength = (data[offset + 2]! << 8) | data[offset + 3]!;
        entries.push({
            group,
            keyLength,
            keyBytes: data.subarray(offset + 4, offset + 4 + keyLength),
        });
        offset += 4 + keyLength;
    }
    return entries;
}

/** Decode a supported_groups / supported_versions list body (2-byte items). */
function decodeUint16List(body: Uint8Array): number[] {
    const listLength = (body[0]! << 8) | body[1]!;
    const items: number[] = [];
    for (let i = 0; i < listLength / 2; i++) {
        items.push((body[2 + i * 2]! << 8) | body[3 + i * 2]!);
    }
    return items;
}

describe("REAL ClientHello emission — chrome-140 vs oracle", () => {
    const profile = getProfile("chrome-140" as ProfileId);

    let transport: CaptureTransport;
    /** The first client write: the record-wrapped initial ClientHello. */
    let record: Uint8Array;
    let hello: ParsedClientHello;
    let connecting: Promise<unknown>;

    beforeAll(async () => {
        transport = new CaptureTransport();
        // Deterministic randomness: the SAME provider feeds key generation,
        // client_random, session id, ECH GREASE bytes, and the per-slot GREASE
        // sentinel draws (handshake-driver derives them from
        // crypto.randomBytes(1)) — so the emitted ClientHello is
        // byte-stable across runs except for the ML-KEM key material, which
        // the noble backend seeds internally (structure-only asserted).
        const deterministicRandom = new DeterministicRandom(GREASE_SEED);
        const deterministicCrypto: CryptoProvider = {
            ...nodeCryptoProvider,
            randomBytes: (length: number) => deterministicRandom.randomBytes(length),
        };

        // The chrome-140 ClientHello config exactly as the profile declares it
        // (profiles 0.2.4): full cipher list including the GREASE placeholder
        // slot, the keyShareGroups / keyShareAdvertisedGroups split, both
        // advertised versions (oracle shape GREASE|0304|0303), and the
        // profile's extension order + record padding.
        const config: ClientHelloConfig = {
            cipherSuites: profile.tls.cipherSuites,
            keyShareGroups: profile.tls.keyShareGroups,
            supportedGroups: profile.tls.keyShareAdvertisedGroups,
            signatureAlgorithms: profile.tls.signatureAlgorithms,
            supportedVersions: [TLS_1_3, TLS_1_2],
            extensionOrder: profile.tls.extensionOrder,
            grease: profile.tls.grease,
            serverName: SERVER_NAME,
            alpnProtocols: ["h2", "http/1.1"],
            ecPointFormats: profile.tls.ecPointFormats,
            recordPadding: profile.tls.recordPadding,
        };

        connecting = connectTls({
            transport,
            serverName: SERVER_NAME,
            profile: config,
            events: captureEventProvider(),
            crypto: deterministicCrypto,
        });
        // The handshake parks on the fake transport's read (no ServerHello);
        // we only need the client's opening record.
        await vi.waitFor(() => {
            expect(transport.writes.length).toBeGreaterThanOrEqual(1);
        });
        record = transport.writes[0]!;
        hello = parseClientHello(record);
    });

    afterAll(async () => {
        // Tear the parked handshake down; the rejection is the expected
        // outcome of aborting before the ServerHello.
        await transport.close();
        await expect(connecting).rejects.toThrow();
    });

    it("opens the initial ClientHello record with legacy version 0x0301", () => {
        // RFC 8446 §5.1: the first record may carry TLS 1.0's version — real
        // Chrome bytes `16 03 01` (golden captures/chrome-131/tls/client_hello.bin
        // opens 16 03 01; tls 0.4.14 threads CLIENT_HELLO_RECORD_VERSION here).
        expect(record[0]).toBe(0x16); // Handshake content type
        expect(record[1]).toBe(0x03);
        expect(record[2]).toBe(0x01);
        // The handshake body itself still declares legacy_version 0x0303.
        expect(hello.legacyVersion).toBe(0x0303);
    });

    it("emits the oracle key_share shape: GREASE(1B 0x00), X25519MLKEM768(1216B), x25519(32B)", () => {
        const keyShare = hello.extensions.find((ext) => ext.type === 0x0033);
        expect(keyShare).toBeDefined();
        const entries = decodeKeyShareEntries(keyShare!);

        // Golden chrome-131: key_share opens `caca 0001 00` — a GREASE group
        // with a ONE-BYTE 0x00 payload (the pre-0.4.14 32-byte blob was a
        // fingerprint divergence), then the real shares.
        expect(entries.length).toBe(3);

        expect(isGreaseValue(entries[0]!.group)).toBe(true);
        expect(entries[0]!.keyLength).toBe(1);
        expect(Array.from(entries[0]!.keyBytes)).toEqual([0x00]);

        // X25519MLKEM768 (0x11ec): 1184-byte ML-KEM encapsulation key + 32-byte
        // X25519 public key = 1216 bytes.
        expect(entries[1]!.group).toBe(0x11ec);
        expect(entries[1]!.keyLength).toBe(1216);

        // x25519 (0x001d): 32 bytes.
        expect(entries[2]!.group).toBe(0x001d);
        expect(entries[2]!.keyLength).toBe(32);
    });

    it("advertises supported_groups GREASE|X25519MLKEM768|x25519|secp256r1|secp384r1", () => {
        const supportedGroups = hello.extensions.find((ext) => ext.type === 0x000a);
        expect(supportedGroups).toBeDefined();
        const groups = decodeUint16List(supportedGroups!.data);

        // Oracle chrome-131 supported_groups: `caca|11ec|001d|0017|0018`. The
        // advertised set is the profile's keyShareAdvertisedGroups (adds
        // secp256r1/secp384r1 over the shared groups), GREASE-prepended.
        expect(groups.length).toBe(5);
        expect(isGreaseValue(groups[0]!)).toBe(true);
        expect(groups.slice(1)).toEqual([4588, 29, 23, 24]);
    });

    it("carries the h2-only 5-byte ALPS body (0x0003 02 'h2')", () => {
        // chrome-140 extensionOrder carries APPLICATION_SETTINGS (17613 =
        // 0x44cd). Oracle: ALPS advertises ONLY h2 — body `00 03 02 68 32`
        // (list length 3, protocol length 2, "h2"). No "http/1.1" entry even
        // though ALPN offers both.
        const alps = hello.extensions.find((ext) => ext.type === 17613);
        expect(alps).toBeDefined();
        expect(Array.from(alps!.data)).toEqual([0x00, 0x03, 0x02, 0x68, 0x32]);
    });

    it("terminates with a 1-byte-body GREASE extension", () => {
        const last = hello.extensions[hello.extensions.length - 1]!;
        // Golden chrome-131 terminates with `5a5a 0001 00` — the trailing
        // GREASE extension carries a single 0x00 body byte (an empty body was
        // the pre-0.4.14 divergence).
        expect(isGreaseValue(last.type)).toBe(true);
        expect(last.length).toBe(1);
        expect(last.data[0]).toBe(0x00);
    });

    it("leads with a GREASE extension and GREASE cipher suite (RFC 8701)", () => {
        // Golden chrome-131: first extension 0x5a5a (empty body), first cipher
        // TLS_GREASE (0x4a4a in the JA3-unstripped wire list).
        expect(isGreaseValue(hello.extensions[0]!.type)).toBe(true);
        expect(hello.extensions[0]!.length).toBe(0);
        expect(isGreaseValue(hello.cipherSuites[0]!)).toBe(true);
    });

    it("draws the six GREASE sentinels independently and pairwise-distinctly", () => {
        // Real Chrome draws each RFC 8701 slot independently (golden
        // chrome-131: cipher 0x5a5a, ext 0x4a4a, key_share/supported_groups
        // 0xcaca in one ClientHello). tls 0.4.14 draws one sentinel per slot;
        // only the two extension slots are forbidden to collide (RFC 8446
        // §4.2 duplicate-extension ban). With GREASE_SEED all six are distinct.
        const supportedVersions = hello.extensions.find((ext) => ext.type === 0x002b)!;
        const versionsBody: number[] = [];
        for (let i = 0; i < supportedVersions.data[0]! / 2; i++) {
            versionsBody.push(
                (supportedVersions.data[1 + i * 2]! << 8) | supportedVersions.data[2 + i * 2]!,
            );
        }

        const supportedGroups = decodeUint16List(
            hello.extensions.find((ext) => ext.type === 0x000a)!.data,
        );
        const keyShareEntries = decodeKeyShareEntries(
            hello.extensions.find((ext) => ext.type === 0x0033)!,
        );

        const sentinels: readonly number[] = [
            hello.cipherSuites[0]!, // cipher-list head
            hello.extensions[0]!.type, // leading extension
            keyShareEntries[0]!.group, // key_share GREASE entry
            supportedGroups[0]!, // supported_groups head
            versionsBody[0]!, // supported_versions head
            hello.extensions[hello.extensions.length - 1]!.type, // trailing extension
        ];

        for (const sentinel of sentinels) {
            expect(isGreaseValue(sentinel)).toBe(true);
            expect(GREASE_VALUES).toContain(sentinel);
        }
        // Pairwise distinct — six slots, six different sentinels.
        expect(new Set(sentinels).size).toBe(6);
        // The non-GREASE supported_versions tail is TLS 1.3 then TLS 1.2
        // (oracle: GREASE|TLS1.3|TLS1.2).
        expect(versionsBody.slice(1)).toEqual([0x0304, 0x0303]);
    });
});
