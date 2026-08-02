/**
 * Real tests for the randomized-field ignore-list comparison (Cat 14 core).
 * Exercises {@link compareBytesWithIgnore} over masked byte ranges.
 */

import { describe, expect, it } from "vitest";
import { compareBytesWithIgnore } from "../src/utils.js";

describe("compareBytesWithIgnore", () => {
    it("reports a match when bytes are equal and no ranges are masked", () => {
        const a = new Uint8Array([1, 2, 3, 4]);
        const result = compareBytesWithIgnore(a, a, []);
        expect(result.matches).toBe(true);
        expect(result.divergenceByteIndex).toBeUndefined();
        expect(result.maskedRanges).toHaveLength(0);
    });

    it("masks a randomized range so a divergence inside it is ignored", () => {
        const a = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x04, 0xaa, 0xbb]);
        const b = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x04, 0xcc, 0xdd]);
        // bytes 5 and 6 differ, but we mask them as the ephemeral key.
        const result = compareBytesWithIgnore(a, b, [
            { byteOffset: 5, length: 2, reason: "ephemeral_key" },
        ]);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges).toHaveLength(1);
    });

    it("still reports divergence outside the masked range", () => {
        const a = new Uint8Array([0x16, 0x03, 0x01, 0xff, 0x04]);
        const b = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x04]);
        // byte 3 differs, but only byte 1 is masked.
        const result = compareBytesWithIgnore(a, b, [
            { byteOffset: 1, length: 1, reason: "nonce" },
        ]);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(3);
    });

    it("supports multiple disjoint masked ranges", () => {
        const a = new Uint8Array([1, 2, 3, 4, 5, 6]);
        const b = new Uint8Array([1, 9, 3, 9, 5, 9]);
        const result = compareBytesWithIgnore(a, b, [
            { byteOffset: 1, length: 1, reason: "grease" },
            { byteOffset: 3, length: 1, reason: "grease" },
            { byteOffset: 5, length: 1, reason: "random" },
        ]);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges).toHaveLength(3);
    });

    it("reports length divergence when one buffer is shorter (outside mask)", () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2]);
        const result = compareBytesWithIgnore(a, b, []);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(2);
    });

    // isMasked() short-circuits to false when the scan index is BEFORE the
    // first masked range (line 81). Exercise that early-return: the divergence
    // is at byte 0, the mask starts at byte 5.
    it("reports a divergence that precedes the masked range", () => {
        const a = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x04, 0xaa, 0xbb]);
        const b = new Uint8Array([0x00, 0x03, 0x01, 0x00, 0x04, 0xaa, 0xbb]);
        const result = compareBytesWithIgnore(a, b, [
            { byteOffset: 5, length: 2, reason: "ephemeral_key" },
        ]);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(0);
    });

    // When one buffer is shorter and the missing bytes fall INSIDE a masked
    // range, the length divergence is skipped (line 92) and the comparison
    // reports a match.
    it("treats a length divergence as a match when the tail is masked", () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2, 3, 9, 9]);
        const result = compareBytesWithIgnore(a, b, [
            { byteOffset: 3, length: 4, reason: "nonce" },
        ]);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges).toHaveLength(1);
    });
});
