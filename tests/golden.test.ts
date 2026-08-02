/**
 * Real tests for golden capture loading + comparison (src/golden/golden.ts).
 *
 * Exercises the on-disk loaders against the in-repo captures, the strict and
 * ignore-list comparators, and the CaptureMeta / RandomizedField validation
 * branches (which are only reachable with a malformed sidecar).
 */

import { describe, expect, it } from "vitest";
import {
    loadGolden,
    loadCaptureMeta,
    compareAgainstGolden,
    compareAgainstGoldenWithIgnore,
    parseCaptureMeta,
    parseRandomizedFields,
} from "../src/golden/golden.js";
import { GoldenMismatchError } from "../src/errors.js";
import type { CaptureId } from "../src/types.js";

const CHROME_CLIENT_HELLO = "chrome-140/tls/client_hello" as CaptureId;

describe("loadGolden / loadCaptureMeta", () => {
    it("loads a golden capture with bytes and metadata", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        expect(capture.id).toBe(CHROME_CLIENT_HELLO);
        expect(capture.protocol).toBe("tls");
        expect(capture.bytes.length).toBeGreaterThan(0);
        expect(capture.description).toContain("ClientHello");
    });

    it("loads the sidecar meta with its randomized fields", () => {
        const meta = loadCaptureMeta(CHROME_CLIENT_HELLO);
        expect(meta.source).toBe("curl-impersonate");
        expect(meta.profile).toBe("chrome-140");
        expect(meta.protocol).toBe("tls");
        expect(meta.record).toBe("client_hello");
        expect(meta.randomizedFields.length).toBeGreaterThan(0);
        expect(typeof meta.createdAt).toBe("string");
    });

    it("throws on a malformed CaptureId", () => {
        expect(() => loadGolden("not-a-valid-id" as CaptureId)).toThrow(/Malformed CaptureId/);
    });
});

describe("compareAgainstGolden (strict)", () => {
    it("reports a match for identical bytes", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        const result = compareAgainstGolden(capture.bytes, CHROME_CLIENT_HELLO);
        expect(result.matches).toBe(true);
        expect(result.divergenceByteIndex).toBeUndefined();
    });

    it("throws GoldenMismatchError when bytes diverge", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        const mutated = new Uint8Array(capture.bytes);
        // Flip a byte in the record header (byte 0) — outside any masked range.
        mutated[0] = mutated[0]! ^ 0xff;
        expect(() => compareAgainstGolden(mutated, CHROME_CLIENT_HELLO)).toThrow(GoldenMismatchError);
    });
});

describe("compareAgainstGoldenWithIgnore (tolerant)", () => {
    it("masks the randomized ranges and reports a match for identical bytes", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        const result = compareAgainstGoldenWithIgnore(capture.bytes, CHROME_CLIENT_HELLO);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges.length).toBeGreaterThan(0);
    });

    it("ignores a divergence that falls inside a masked range", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        const meta = loadCaptureMeta(CHROME_CLIENT_HELLO);
        const mutated = new Uint8Array(capture.bytes);
        // Flip the first byte of the client_random (offset 12) — masked as "random".
        const range = meta.randomizedFields.find((r) => r.reason === "random");
        expect(range).toBeDefined();
        mutated[range!.byteOffset] = mutated[range!.byteOffset]! ^ 0xff;
        const result = compareAgainstGoldenWithIgnore(mutated, CHROME_CLIENT_HELLO);
        expect(result.matches).toBe(true);
    });

    it("throws GoldenMismatchError for a divergence outside the masked ranges", () => {
        const capture = loadGolden(CHROME_CLIENT_HELLO);
        const mutated = new Uint8Array(capture.bytes);
        mutated[0] = mutated[0]! ^ 0xff; // record header — not masked
        expect(() => compareAgainstGoldenWithIgnore(mutated, CHROME_CLIENT_HELLO)).toThrow(
            GoldenMismatchError,
        );
    });
});

describe("parseCaptureMeta validation", () => {
    const valid = {
        source: "curl-impersonate",
        profile: "chrome-140",
        protocol: "tls",
        record: "client_hello",
        description: "d",
        randomizedFields: [{ byteOffset: 0, length: 1, reason: "random" }],
        createdAt: "2026-08-02T00:00:00Z",
    };

    it("accepts a well-formed meta object", () => {
        const parsed = parseCaptureMeta(valid, CHROME_CLIENT_HELLO);
        expect(parsed.source).toBe("curl-impersonate");
        expect(parsed.protocol).toBe("tls");
    });

    it("rejects a non-object", () => {
        expect(() => parseCaptureMeta(null, CHROME_CLIENT_HELLO)).toThrow(/not an object/);
        expect(() => parseCaptureMeta("string", CHROME_CLIENT_HELLO)).toThrow(/not an object/);
    });

    it("rejects an invalid source", () => {
        expect(() => parseCaptureMeta({ ...valid, source: "mitmproxy" }, CHROME_CLIENT_HELLO)).toThrow(
            /invalid source/,
        );
    });

    it("rejects an invalid protocol", () => {
        expect(() => parseCaptureMeta({ ...valid, protocol: "quic" }, CHROME_CLIENT_HELLO)).toThrow(
            /invalid protocol/,
        );
    });

    it("rejects an invalid record", () => {
        expect(() => parseCaptureMeta({ ...valid, record: "payload" }, CHROME_CLIENT_HELLO)).toThrow(
            /invalid record/,
        );
    });

    it("rejects a non-string description", () => {
        expect(() => parseCaptureMeta({ ...valid, description: 42 }, CHROME_CLIENT_HELLO)).toThrow(
            /non-string description/,
        );
    });

    it("rejects a non-string createdAt", () => {
        expect(() => parseCaptureMeta({ ...valid, createdAt: 0 }, CHROME_CLIENT_HELLO)).toThrow(
            /non-string createdAt/,
        );
    });
});

describe("parseRandomizedFields validation", () => {
    const base = {
        source: "curl-impersonate",
        profile: "chrome-140",
        protocol: "tls",
        record: "client_hello",
        description: "d",
        createdAt: "2026-08-02T00:00:00Z",
    };

    it("accepts a well-formed field list", () => {
        const fields = parseRandomizedFields(
            [{ byteOffset: 0, length: 1, reason: "random" }],
            CHROME_CLIENT_HELLO,
        );
        expect(fields).toHaveLength(1);
    });

    it("rejects a non-array", () => {
        expect(() => parseRandomizedFields("nope", CHROME_CLIENT_HELLO)).toThrow(/non-array/);
    });

    it("rejects a non-object entry", () => {
        expect(() => parseRandomizedFields([123], CHROME_CLIENT_HELLO)).toThrow(
            /is not an object/,
        );
    });

    it("rejects an invalid byteOffset", () => {
        expect(() =>
            parseRandomizedFields(
                [{ byteOffset: -1, length: 1, reason: "random" }],
                CHROME_CLIENT_HELLO,
            ),
        ).toThrow(/byteOffset invalid/);
    });

    it("rejects an invalid length", () => {
        expect(() =>
            parseRandomizedFields(
                [{ byteOffset: 0, length: -5, reason: "random" }],
                CHROME_CLIENT_HELLO,
            ),
        ).toThrow(/length invalid/);
    });

    it("rejects an invalid reason", () => {
        expect(() =>
            parseRandomizedFields(
                [{ byteOffset: 0, length: 1, reason: "guess" }],
                CHROME_CLIENT_HELLO,
            ),
        ).toThrow(/reason invalid/);
    });

    it("exposes the field list through parseCaptureMeta", () => {
        const parsed = parseCaptureMeta(
            {
                ...base,
                randomizedFields: [
                    { byteOffset: 12, length: 32, reason: "random" },
                    { byteOffset: 49, length: 32, reason: "ephemeral_key" },
                ],
            },
            CHROME_CLIENT_HELLO,
        );
        expect(parsed.randomizedFields).toHaveLength(2);
        expect(parsed.randomizedFields[0]!.reason).toBe("random");
    });
});
