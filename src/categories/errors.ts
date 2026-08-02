/**
 * Test Category 13 — Error Handling.
 *
 * Verify behavior under invalid / adversarial conditions, and that the
 * project's typed error classes instantiate correctly.
 *
 * See docs/TEST-SUITE.md ("Test Category 13 — Error Handling") for full
 * acceptance criteria.
 */

import { describe, expect, it } from "vitest";
import { GoldenMismatchError, TestingError } from "../errors.js";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.ErrorHandling;

describe(CATEGORY_ID, () => {
    // Trivially-testable: the typed error classes must instantiate and carry
    // their discriminant + cause. These exercise existing utils (errors.ts).
    it("TestingError instantiates with a kind discriminant and optional cause", () => {
        const cause = new Error("underlying");
        const err = new TestingError("boom", { cause });
        expect(err).toBeInstanceOf(TestingError);
        expect(err.kind).toBe("TestingError");
        expect(err.message).toBe("boom");
        expect(err.cause).toBe(cause);
    });

    it("GoldenMismatchError records the capture id and divergence index", () => {
        const err = new GoldenMismatchError("chrome-140:client-hello:1", 42);
        expect(err).toBeInstanceOf(GoldenMismatchError);
        expect(err.kind).toBe("GoldenMismatchError");
        expect(err.captureId).toBe("chrome-140:client-hello:1");
        expect(err.divergenceByteIndex).toBe(42);
        expect(err.message).toContain("diverges at byte 42");
    });

    it.todo("invalid certificates");
    it.todo("unsupported cipher");
    it.todo("unexpected alerts");
    it.todo("truncated packets");
    it.todo("invalid HTTP responses");
    it.todo("timeout handling");
    it.todo("broken TCP connections");
});
