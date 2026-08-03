/**
 * Tests for golden capture loading error paths + parseSource coverage
 * (src/golden/golden.ts).
 *
 * golden.test.ts covers the happy path and the CaptureMeta validators. This
 * file exercises the file-system failure branches (missing .bin / .meta),
 * the load-failure catch in both comparators, and parseSource via the
 * firefox capture (different profile branch).
 */

import { describe, expect, it } from "vitest";
import {
    loadGolden,
    loadCaptureMeta,
    compareAgainstGolden,
    compareAgainstGoldenWithIgnore,
} from "../src/golden/golden.js";
import { TestingError } from "../src/errors.js";
import type { CaptureId } from "../src/types.js";

const CHROME = "chrome-140/tls/client_hello" as CaptureId;
const FIREFOX = "firefox-128/tls/client_hello" as CaptureId;
// A well-formed CaptureId that resolves to files that do not exist on disk.
const MISSING = "chrome-140/tls/server_hello" as CaptureId;

describe("loadGolden file-system errors", () => {
    it("throws TestingError when the .bin is missing", () => {
        expect(() => loadGolden(MISSING)).toThrow(TestingError);
        expect(() => loadGolden(MISSING)).toThrow(/Failed to read capture bytes/);
    });

    it("attaches the original FS error as .cause", () => {
        try {
            loadGolden(MISSING);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(TestingError);
            expect((e as TestingError).cause).toBeInstanceOf(Error);
        }
    });
});

describe("loadCaptureMeta file-system errors", () => {
    it("throws TestingError when the .meta.json is missing", () => {
        expect(() => loadCaptureMeta(MISSING)).toThrow(TestingError);
        expect(() => loadCaptureMeta(MISSING)).toThrow(/Failed to read\/parse capture meta/);
    });

    it("attaches the original error as .cause", () => {
        try {
            loadCaptureMeta(MISSING);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect((e as TestingError).cause).toBeInstanceOf(Error);
        }
    });
});

describe("parseSource via different profile captures", () => {
    it("maps the chrome profile to source chrome-140", () => {
        expect(loadGolden(CHROME).source).toBe("chrome-140");
    });

    it("maps the firefox profile to source firefox-135", () => {
        // Exercises the firefox branch of parseSource — previously uncovered
        // because only the chrome capture was loaded.
        expect(loadGolden(FIREFOX).source).toBe("firefox-135");
    });
});

describe("compareAgainstGolden load failures", () => {
    it("wraps a missing-capture load error in TestingError", () => {
        expect(() => compareAgainstGolden(new Uint8Array([0]), MISSING)).toThrow(TestingError);
        expect(() => compareAgainstGolden(new Uint8Array([0]), MISSING)).toThrow(
            /Failed to load golden/,
        );
    });

    it("attaches the underlying error as cause", () => {
        try {
            compareAgainstGolden(new Uint8Array([0]), MISSING);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect((e as TestingError).cause).toBeInstanceOf(Error);
        }
    });
});

describe("compareAgainstGoldenWithIgnore load failures", () => {
    it("wraps a missing-capture load error in TestingError", () => {
        expect(() => compareAgainstGoldenWithIgnore(new Uint8Array([0]), MISSING)).toThrow(
            TestingError,
        );
        expect(() => compareAgainstGoldenWithIgnore(new Uint8Array([0]), MISSING)).toThrow(
            /Failed to load golden/,
        );
    });

    it("attaches the underlying error as cause", () => {
        try {
            compareAgainstGoldenWithIgnore(new Uint8Array([0]), MISSING);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect((e as TestingError).cause).toBeInstanceOf(Error);
        }
    });

    it("reports the full maskedRanges list on a tolerant match", () => {
        // Re-run the tolerant happy path to confirm maskedRanges is populated
        // from the sidecar (the firefox capture also has randomized fields).
        const capture = loadGolden(FIREFOX);
        const result = compareAgainstGoldenWithIgnore(capture.bytes, FIREFOX);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges.length).toBeGreaterThan(0);
    });
});
