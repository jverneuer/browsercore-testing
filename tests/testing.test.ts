import { describe, expect, it } from "vitest";
import { compareBytes, bytesToHex } from "../src/index.js";

describe("bytesToHex", () => {
    it("formats bytes as lowercase hex with no separators", () => {
        expect(bytesToHex(new Uint8Array([0, 1, 255]))).toBe("0001ff");
    });

    it("returns an empty string for an empty buffer", () => {
        expect(bytesToHex(new Uint8Array([]))).toBe("");
    });
});

describe("compareBytes", () => {
    it("reports matching for equal bytes", () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2, 3]);
        const result = compareBytes(a, b);
        expect(result.matches).toBe(true);
        expect(result.divergenceByteIndex).toBeUndefined();
        expect(result.message).toBe("equal");
    });

    it("reports the first divergence index for unequal bytes", () => {
        const a = new Uint8Array([1, 2, 3, 4]);
        const b = new Uint8Array([1, 2, 9, 4]);
        const result = compareBytes(a, b);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(2);
    });

    it("reports divergence at the prefix when lengths differ", () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2]);
        const result = compareBytes(a, b);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(2);
    });
});
