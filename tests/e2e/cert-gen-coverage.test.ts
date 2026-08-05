/**
 * Coverage-targeted tests for the branches holding src/e2e/cert-gen.ts
 * below 94%.
 *
 * sink-server.test.ts exercises generateSelfSignedCert()'s public surface
 * (DER/PEM shape, secure-context loading, custom SANs). The remaining
 * uncovered branch is the `arc === 0` path inside the internal derOid()
 * helper (cert-gen.ts lines 85-86): when an OID arc beyond the first two is
 * exactly 0, it is encoded as a single 0x00 byte instead of running the
 * base-128 loop. None of the OIDs hard-coded in generateSelfSignedCert
 * ("2.5.4.3", "2.5.29.17", …) contain a zero arc, so that branch is
 * unreachable through the public API. We cover it by calling derOid()
 * directly with an OID that has a zero arc.
 */

import { describe, expect, it } from "vitest";
import { derOid } from "../../src/e2e/cert-gen.js";

describe("derOid — arc === 0 branch (cert-gen.ts lines 85-86)", () => {
    it("encodes a trailing zero arc as a single 0x00 byte", () => {
        // OID 2.5.4.0: first = 2*40 + 5 = 85 = 0x55.
        // arcs beyond the first two: [4, 0].
        //   arc=4  → base-128 → [0x04]
        //   arc=0  → the `arc === 0` branch → [0x00]
        // content = [0x55, 0x04, 0x00], length 3.
        // DER OID TLV: tag 0x06, length 0x03, then content.
        const encoded = derOid("2.5.4.0");
        expect(encoded).toEqual(new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x00]));
    });

    it("encodes a zero arc that follows a multi-byte base-128 arc", () => {
        // OID 2.5.4.128.0: first = 85 = 0x55.
        // arcs beyond the first two: [4, 128, 0].
        //   arc=4   → [0x04]
        //   arc=128 → base-128: 128 = 0b10000000 → [0x81, 0x00]
        //             (low byte (128 & 0x7f)=0 with continuation 0x80 → 0x80;
        //              then 128>>7=1, (1 & 0x7f)|0 = 1 → unshift → [1, 0x80])
        //   arc=0   → the `arc === 0` branch → [0x00]
        // content = [0x55, 0x04, 0x81, 0x00, 0x00], length 5.
        const encoded = derOid("2.5.4.128.0");
        expect(encoded).toEqual(
            new Uint8Array([0x06, 0x05, 0x55, 0x04, 0x81, 0x00, 0x00]),
        );
    });

    it("encodes a leading zero arc right after the first two", () => {
        // OID 2.5.0.3: first = 85 = 0x55.
        // arcs beyond the first two: [0, 3].
        //   arc=0 → the `arc === 0` branch → [0x00]
        //   arc=3 → base-128 → [0x03]
        // content = [0x55, 0x00, 0x03], length 3.
        const encoded = derOid("2.5.0.3");
        expect(encoded).toEqual(new Uint8Array([0x06, 0x03, 0x55, 0x00, 0x03]));
    });

    it("still encodes a normal (non-zero) multi-arc OID correctly", () => {
        // Sanity check: the non-zero path is unchanged.
        // OID 2.5.4.3 (commonName): first = 85, arcs [4, 3] → [0x04, 0x03].
        const encoded = derOid("2.5.4.3");
        expect(encoded).toEqual(new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x03]));
    });
});
