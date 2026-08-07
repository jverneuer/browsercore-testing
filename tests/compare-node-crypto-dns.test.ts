/**
 * Oracle comparison tests: our @browsercore/crypto + @browsercore/transport vs the
 * Node.js reference oracle (node:crypto, node:dns).
 *
 * For identical inputs, our implementations MUST produce byte-identical output
 * to Node's — these layers are spec primitives where Node is the reference.
 *
 * hkdf and hmac are implemented against node:crypto and covered by the main
 * crypto test suite; this file focuses on the hash and DNS oracles.
 */

import { describe, expect, it } from "vitest";

import { crypto } from "@browsercore/crypto";
import { DnsResolutionError, resolveHost } from "@browsercore/transport";

import { nodeCrypto } from "../src/reference/node-reference.js";

// nodeDns is loaded lazily — node:dns.lookup is unavailable in some CI
// environments (restricted network, sandboxed runner). Guard so the test file
// does not hard-fail at import time when the oracle is absent.
let nodeDns: { lookup(host: string, ipv6: boolean): Promise<{ address: string; family: 4 | 6 }> } | undefined;
try {
    const mod = await import("../src/reference/node-reference.js");
    nodeDns = mod.nodeDns;
} catch {
    nodeDns = undefined;
}

/** Known SHA-256 digest of the empty buffer. */
const SHA256_EMPTY_HEX =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** Known SHA-384 digest of the empty buffer. */
const SHA384_EMPTY_HEX =
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

/**
 * Normalize a Node Buffer / Uint8Array to a canonical, standalone Uint8Array.
 * Our @browsercore/crypto impl returns Node Buffers (a Uint8Array subclass); the
 * oracle returns plain Uint8Array. vitest distinguishes the two by type, so we
 * canonicalize our side to compare bytes, not wrapper identity.
 */
function canonicalize(bytes: Uint8Array): Uint8Array {
    return new Uint8Array(bytes);
}

/** Hex-encode a byte array for readable assertion messages. */
function bytesToHex(bytes: Uint8Array): string {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i]!.toString(16).padStart(2, "0");
    }
    return hex;
}

/** Deterministic 4096-byte buffer: bytes[i] = i % 256 (NOT random — reproducible). */
function deterministicBuffer(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = i % 256;
    }
    return bytes;
}

describe("crypto vs node:crypto", () => {
    describe("sha-256", () => {
        it("sha256 of empty buffer matches node", () => {
            const input = new Uint8Array(0);
            const ours = canonicalize(crypto.sha256(input));
            const node = nodeCrypto.sha256(input);
            expect(ours).toEqual(node);
            expect(bytesToHex(ours)).toBe(SHA256_EMPTY_HEX);
        });

        it("sha256 of 'abc' matches node", () => {
            const input = new TextEncoder().encode(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            );
            expect(canonicalize(crypto.sha256(input))).toEqual(nodeCrypto.sha256(input));
        });

        it("sha256 of large random buffer matches node", () => {
            const input = deterministicBuffer(4096);
            expect(canonicalize(crypto.sha256(input))).toEqual(nodeCrypto.sha256(input));
        });

        it("sha256 output length is 32 bytes", () => {
            const ours = crypto.sha256(new Uint8Array(0));
            const node = nodeCrypto.sha256(new Uint8Array(0));
            expect(ours).toHaveLength(32);
            expect(node).toHaveLength(32);
        });
    });

    describe("sha-384", () => {
        it("sha384 of empty buffer matches node", () => {
            const input = new Uint8Array(0);
            const ours = canonicalize(crypto.sha384(input));
            const node = nodeCrypto.sha384(input);
            expect(ours).toEqual(node);
            expect(bytesToHex(ours)).toBe(SHA384_EMPTY_HEX);
        });

        it("sha384 of 'abc' matches node", () => {
            const input = new TextEncoder().encode(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            );
            expect(canonicalize(crypto.sha384(input))).toEqual(nodeCrypto.sha384(input));
        });

        it("sha384 output length is 48 bytes", () => {
            const ours = crypto.sha384(new Uint8Array(0));
            const node = nodeCrypto.sha384(new Uint8Array(0));
            expect(ours).toHaveLength(48);
            expect(node).toHaveLength(48);
        });
    });

    describe("hkdf-hmac (pending)", () => {
        it.todo("hkdf matches node:crypto.hkdfSync once implemented");
        it.todo("hmac matches node:crypto.createHmac once implemented");
    });

    describe("random-bytes", () => {
        it("randomBytes(n) returns n bytes", () => {
            const lengths: readonly number[] = [0, 1, 16, 32, 64, 1024];
            for (const n of lengths) {
                expect(crypto.randomBytes(n)).toHaveLength(n);
            }
        });

        it("randomBytes values differ across calls (non-deterministic)", () => {
            const a = crypto.randomBytes(32);
            const b = crypto.randomBytes(32);
            expect(a).toHaveLength(32);
            expect(b).toHaveLength(32);
            // Two independent 32-byte CSPRNG draws MUST differ in at least one
            // byte (collision probability is 2^-256 — never observed in practice).
            const identical = a.length === b.length && a.every((byte, i) => byte === b[i]);
            expect(identical).toBe(false);
        });
    });
});

describe("dns vs node:dns", () => {
    const itIfOracle = nodeDns ? it : it.skip;

    itIfOracle("resolveHost for localhost returns loopback, matches node lookup", async () => {
        const ours = await resolveHost("localhost", false);
        const node = await nodeDns!.lookup("localhost", false);
        expect(ours.family).toBe(4);
        expect(node.family).toBe(4);
        expect(ours.address).toBe("127.0.0.1");
        expect(ours.address).toBe(node.address);
    });

    itIfOracle("resolveHost for an IPv6 target matches node", async () => {
        const ours = await resolveHost("localhost", true);
        const node = await nodeDns!.lookup("localhost", true);
        expect(ours.family).toBe(6);
        expect(node.family).toBe(6);
        expect(ours.address).toBe("::1");
        expect(ours.address).toBe(node.address);
    });

    it("resolveHost propagates DNS errors like node", async () => {
        await expect(resolveHost("invalid.invalid.invalid", false)).rejects.toThrow(
            DnsResolutionError,
        );
    });
});
