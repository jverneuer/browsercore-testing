/**
 * Tests for the typed error classes. The GoldenMismatchError branch coverage
 * gap is the optional `cause` constructor argument — exercise both with and
 * without it so both branches of `options?.cause` are covered.
 */

import { describe, expect, it } from "vitest";
import { GoldenMismatchError, TestingError } from "../src/errors.js";

describe("TestingError", () => {
    it("instantiates without a cause", () => {
        const err = new TestingError("boom");
        expect(err).toBeInstanceOf(TestingError);
        expect(err.kind).toBe("TestingError");
        expect(err.message).toBe("boom");
        expect(err.cause).toBeUndefined();
    });

    it("carries an optional cause", () => {
        const cause = new Error("underlying");
        const err = new TestingError("boom", { cause });
        expect(err.cause).toBe(cause);
    });
});

describe("GoldenMismatchError", () => {
    it("instantiates without a cause", () => {
        const err = new GoldenMismatchError("chrome-140/tls/client_hello", 42);
        expect(err).toBeInstanceOf(GoldenMismatchError);
        expect(err.kind).toBe("GoldenMismatchError");
        expect(err.captureId).toBe("chrome-140/tls/client_hello");
        expect(err.divergenceByteIndex).toBe(42);
        expect(err.cause).toBeUndefined();
        expect(err.message).toContain("diverges at byte 42");
    });

    it("carries an optional cause", () => {
        const cause = new Error("io");
        const err = new GoldenMismatchError("chrome-140/tls/client_hello", 7, { cause });
        expect(err.cause).toBe(cause);
    });
});
