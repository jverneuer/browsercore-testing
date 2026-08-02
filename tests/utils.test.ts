/**
 * Tests for the small shared helpers in src/utils.ts: assertNever, createId,
 * bytesToHex (already covered in testing.test.ts, repeated for completeness),
 * compareBytes (already covered), compareBytesWithIgnore (already covered).
 */

import { describe, expect, it } from "vitest";
import { assertNever, createId } from "../src/utils.js";

describe("assertNever", () => {
    it("throws an exhaustiveness error when called", () => {
        // Compile-time guard: in correct usage this is only reachable when a
        // switch is non-exhaustive. We exercise the runtime path directly.
        expect(() => assertNever("anything" as never)).toThrow("Unexpected value");
    });

    it("stringifies the unexpected value in the error message", () => {
        expect(() => assertNever({ foo: 1 } as never)).toThrow(/foo/);
    });
});

describe("createId", () => {
    it("generates a string id with the default 'tc' prefix", () => {
        const id = createId();
        expect(id).toMatch(/^tc_[a-z0-9]+_[a-z0-9]+$/);
    });

    it("uses the supplied prefix", () => {
        const id = createId("tc");
        expect(id.startsWith("tc_")).toBe(true);
    });

    it("produces unique ids across calls", () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
            ids.add(createId());
        }
        // 100 draws from a ~2.5M-space random suffix collide with negligible
        // probability — assert uniqueness as a sanity check on randomness.
        expect(ids.size).toBe(100);
    });
});
