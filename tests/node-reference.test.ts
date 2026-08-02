/**
 * Tests for the Node.js reference oracle (src/reference/node-reference.ts).
 *
 * The primitive-layer oracles (nodeCrypto/nodeDns/nodeZlib/nodeHttp) are
 * exercised against our @browsercore/* packages in the compare-node-* suites;
 * this file targets the uncovered helpers: {@link compareBytesOutcome}'s
 * not-equal branches and the {@link firstDiff} locator they call.
 */

import { describe, expect, it } from "vitest";
import { compareBytesOutcome } from "../src/reference/node-reference.js";

describe("compareBytesOutcome", () => {
    it("reports equal for byte-identical buffers", () => {
        const a = new Uint8Array([1, 2, 3]);
        expect(compareBytesOutcome(a, a)).toEqual({ equal: true });
    });

    it("reports a length mismatch when the buffers differ in size", () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2]);
        expect(compareBytesOutcome(a, b)).toEqual({
            equal: false,
            reason: "length 3 vs 2",
        });
    });

    it("locates the first differing byte when lengths match", () => {
        const a = new Uint8Array([1, 2, 3, 4]);
        const b = new Uint8Array([1, 2, 9, 4]);
        expect(compareBytesOutcome(a, b)).toEqual({
            equal: false,
            reason: "length 4 vs 4, first diff at byte 2",
        });
    });

    it("reports the first diff at byte 0 when the leading bytes diverge", () => {
        const a = new Uint8Array([0xa1, 0xb2]);
        const b = new Uint8Array([0xc3, 0xb2]);
        expect(compareBytesOutcome(a, b)).toEqual({
            equal: false,
            reason: "length 2 vs 2, first diff at byte 0",
        });
    });
});
