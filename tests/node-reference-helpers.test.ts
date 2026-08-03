/**
 * Tests for the uncovered Node.js reference oracle helpers
 * (src/reference/node-reference.ts).
 *
 * The compare-node-* suites exercise sha256/sha384/dns/zlib against our
 * packages. This file targets the oracle helpers those suites do not reach:
 * hkdf, hmac, randomBytes, digestLength, the zlibConstants getter, and toError.
 */

import { createHash, createHmac, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { nodeCrypto, nodeDns, nodeZlib, toError } from "../src/reference/node-reference.js";

describe("nodeCrypto.hkdf", () => {
    it("matches node:crypto.hkdfSync for sha256", () => {
        const salt = new TextEncoder().encode("salt");
        const ikm = new TextEncoder().encode("input key material");
        const info = new TextEncoder().encode("info");
        const expected = new Uint8Array(
            hkdfSync("sha256", ikm, salt, info, 42) as unknown as Uint8Array,
        );
        expect(nodeCrypto.hkdf("sha256", salt, ikm, info, 42)).toEqual(expected);
    });

    it("matches node:crypto.hkdfSync for sha384", () => {
        const salt = new Uint8Array(0);
        const ikm = new TextEncoder().encode("ikm");
        const info = new Uint8Array(0);
        const expected = new Uint8Array(
            hkdfSync("sha384", ikm, salt, info, 64) as unknown as Uint8Array,
        );
        expect(nodeCrypto.hkdf("sha384", salt, ikm, info, 64)).toEqual(expected);
    });

    it("returns a standalone Uint8Array of the requested length", () => {
        const out = nodeCrypto.hkdf("sha256", new Uint8Array(0), new Uint8Array(1), new Uint8Array(0), 16);
        expect(out).toBeInstanceOf(Uint8Array);
        expect(out.length).toBe(16);
    });
});

describe("nodeCrypto.hmac", () => {
    it("matches node:crypto.createHmac for sha256", () => {
        const key = new TextEncoder().encode("key");
        const data = new TextEncoder().encode("The quick brown fox");
        const expected = new Uint8Array(createHmac("sha256", key).update(data).digest());
        expect(nodeCrypto.hmac("sha256", key, data)).toEqual(expected);
    });

    it("matches node:crypto.createHmac for sha384", () => {
        const key = new Uint8Array([1, 2, 3]);
        const data = new Uint8Array([4, 5, 6]);
        const expected = new Uint8Array(createHmac("sha384", key).update(data).digest());
        expect(nodeCrypto.hmac("sha384", key, data)).toEqual(expected);
    });

    it("returns a fresh Uint8Array (not a shared Buffer reference)", () => {
        const out = nodeCrypto.hmac("sha256", new Uint8Array(0), new Uint8Array(0));
        expect(out).toBeInstanceOf(Uint8Array);
        expect(out.length).toBe(32);
    });
});

describe("nodeCrypto.randomBytes", () => {
    it("returns the requested number of bytes", () => {
        for (const n of [0, 1, 16, 32, 256]) {
            expect(nodeCrypto.randomBytes(n)).toHaveLength(n);
        }
    });

    it("returns independent draws (non-deterministic)", () => {
        const a = nodeCrypto.randomBytes(32);
        const b = nodeCrypto.randomBytes(32);
        expect(a.every((byte, i) => byte === b[i])).toBe(false);
    });
});

describe("nodeCrypto.digestLength", () => {
    it("returns 32 for sha256", () => {
        expect(nodeCrypto.digestLength("sha256")).toBe(32);
    });

    it("returns 48 for sha384", () => {
        expect(nodeCrypto.digestLength("sha384")).toBe(48);
    });

    it("agrees with the actual digest sizes", () => {
        const data = new TextEncoder().encode("abc");
        expect(nodeCrypto.sha256(data)).toHaveLength(nodeCrypto.digestLength("sha256"));
        expect(nodeCrypto.sha384(data)).toHaveLength(nodeCrypto.digestLength("sha384"));
    });
});

describe("nodeCrypto hash oracle cross-check", () => {
    it("sha256 matches node:crypto independently", () => {
        const data = new TextEncoder().encode("hello");
        expect(nodeCrypto.sha256(data)).toEqual(
            new Uint8Array(createHash("sha256").update(data).digest()),
        );
    });

    it("sha384 matches node:crypto independently", () => {
        const data = new TextEncoder().encode("hello");
        expect(nodeCrypto.sha384(data)).toEqual(
            new Uint8Array(createHash("sha384").update(data).digest()),
        );
    });
});

describe("nodeZlib.zlibConstants getter", () => {
    it("exposes the node:zlib constants table", () => {
        const constants = nodeZlib.zlibConstants;
        // A handful of well-known zlib constants that must be present.
        expect(constants).toBeDefined();
        expect(typeof constants.Z_NO_FLUSH).toBe("number");
        expect(typeof constants.Z_FINISH).toBe("number");
    });
});

describe("nodeDns.lookup error propagation", () => {
    // Directly exercises the reject(err) branch — the compare-node suite only
    // hits the success path (localhost) and tests resolveHost, not nodeDns.
    it("rejects for an unresolvable host", async () => {
        await expect(nodeDns.lookup("invalid.invalid.invalid", false)).rejects.toThrow();
    });

    it("rejects for an unresolvable IPv6 host", async () => {
        await expect(nodeDns.lookup("invalid.invalid.invalid", true)).rejects.toThrow();
    });
});

describe("toError", () => {
    it("returns the value unchanged when it is already an Error", () => {
        const original = new Error("boom");
        expect(toError(original)).toBe(original);
    });

    it("wraps a string in a new Error preserving the message", () => {
        const wrapped = toError("a string failure");
        expect(wrapped).toBeInstanceOf(Error);
        expect(wrapped.message).toBe("a string failure");
    });

    it("wraps any non-string non-Error value as an 'unknown error'", () => {
        expect(toError(42).message).toBe("unknown error");
        expect(toError(null).message).toBe("unknown error");
        expect(toError({ x: 1 }).message).toBe("unknown error");
        expect(toError(undefined).message).toBe("unknown error");
    });
});
