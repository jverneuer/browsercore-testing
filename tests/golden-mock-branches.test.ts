/**
 * Mock-based branch coverage for src/golden/golden.ts.
 *
 * The remaining uncovered branches in golden.ts fall into two camps:
 *
 *  1. Defensive paths that the real node:fs can never exercise — e.g. the
 *     `e instanceof Error ? e : new Error(String(e))` fallback when fs throws
 *     a non-Error (it never does), the `?? actual.length` fallback when
 *     `compareBytes` already guarantees a defined divergence index, and the
 *     `profile === undefined` guard after a verified 3-part split. These are
 *     unreachable without source changes and are NOT targeted here.
 *
 *  2. Conditional paths that ARE reachable but require controlling what
 *     `readFileSync` returns or throws — the meta-read failure path inside
 *     `loadGolden` (distinct from `loadCaptureMeta`'s own failure), the
 *     "real-browser" source branch of the source ternary, the non-safari /
 *     edge / fallback branches of `parseSource`, and the non-Error catch
 *     branches in `loadGolden` / `loadCaptureMeta`.
 *
 * We mock `node:fs#readFileSync` to drive these paths deterministically.
 * Each test maps to a specific uncovered branch in the v8 report.
 */

import { vi, describe, expect, it, afterEach } from "vitest";

// Hoisted mock so the vi.mock factory below can reference it regardless of
// vitest's hoist order.
const { mockReadFileSync } = vi.hoisted(() => ({
    mockReadFileSync: vi.fn<
        (path: string, encoding?: string | null) => Uint8Array | string
    >(),
}));

vi.mock("node:fs", () => ({ readFileSync: mockReadFileSync }));

import { loadGolden, loadCaptureMeta } from "../src/golden/golden.js";
import { TestingError } from "../src/errors.js";
import type { CaptureId } from "../src/types.js";

const CHROME = "chrome-140/tls/client_hello" as CaptureId;

const BIN_BYTES = new Uint8Array([0x03, 0x03, 0x01, 0x02, 0x03]);

/**
 * Build a valid CaptureMeta-shaped object (parseCaptureMeta's validator only
 * constrains source/protocol/record/description/createdAt/randomizedFields —
 * `profile` is an unchecked cast, so any string passes).
 */
function meta(source: "curl-impersonate" | "real-browser", profile: string): Record<string, unknown> {
    return {
        source,
        profile,
        protocol: "tls",
        record: "client_hello",
        description: "synthetic fixture for branch coverage",
        randomizedFields: [],
        createdAt: "2026-08-02T00:00:00Z",
    };
}

/**
 * Install a readFileSync mock. `bin` controls the `.bin` read, `meta` the
 * `.meta.json` read. Each may succeed (return bytes / JSON string) or throw.
 */
function installMock(bin: { kind: "ok"; bytes: Uint8Array } | { kind: "throw"; value: unknown }, meta: { kind: "ok"; json: Record<string, unknown> } | { kind: "throw"; value: unknown }): void {
    mockReadFileSync.mockImplementation((path: string): Uint8Array | string => {
        if (path.endsWith(".bin")) {
            if (bin.kind === "throw") throw bin.value;
            return bin.bytes;
        }
        if (path.endsWith(".meta.json")) {
            if (meta.kind === "throw") throw meta.value;
            return JSON.stringify(meta.json);
        }
        throw new Error(`mock readFileSync: unexpected path ${path}`);
    });
}

afterEach(() => {
    mockReadFileSync.mockReset();
});

describe("loadGolden — bin-read catch, non-Error thrown (branch 22)", () => {
    it("wraps a non-Error throw as `new Error(String(e))`", () => {
        // readFileSync normally throws Error subclasses; the defensive
        // `: new Error(String(e))` branch only fires for non-Error values.
        installMock({ kind: "throw", value: 42 }, { kind: "throw", value: 42 });
        expect(() => loadGolden(CHROME)).toThrow(TestingError);
        expect(() => loadGolden(CHROME)).toThrow(/Failed to read capture bytes/);
    });
});

describe("loadGolden — meta-read catch (branch 23, both locations)", () => {
    it("catches an Error from the meta read and uses it as the cause (loc 0)", () => {
        // Bin read succeeds (so we reach the meta read); meta read throws an
        // Error → the `e instanceof Error` true branch is taken.
        const boom = new Error("meta read failed");
        installMock({ kind: "ok", bytes: BIN_BYTES }, { kind: "throw", value: boom });
        try {
            loadGolden(CHROME);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(TestingError);
            expect((e as TestingError).cause).toBe(boom);
        }
    });

    it("catches a non-Error from the meta read and wraps it (loc 1)", () => {
        // Meta read throws a non-Error → the `: new Error(String(e))` branch.
        installMock({ kind: "ok", bytes: BIN_BYTES }, { kind: "throw", value: "boom" });
        try {
            loadGolden(CHROME);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(TestingError);
            expect((e as TestingError).cause).toBeInstanceOf(Error);
            expect((e as TestingError).cause!.message).toBe("boom");
        }
    });
});

describe("loadGolden — source ternary, real-browser branch (branch 24)", () => {
    it("returns \"chrome-140\" when the sidecar source is real-browser", () => {
        // parsed.source === "real-browser" → ternary else branch → "chrome-140"
        // (and parseSource is NOT called).
        installMock({ kind: "ok", bytes: BIN_BYTES }, { kind: "ok", json: meta("real-browser", "chrome-140") });
        const capture = loadGolden(CHROME);
        expect(capture.source).toBe("chrome-140");
    });
});

describe("parseSource — non-safari, edge, and fallback branches (branches 27-28)", () => {
    it("routes an edge profile through the safari-else and edge-true branches", () => {
        // profile "edge-140" → not chrome, not firefox → reaches safari check
        // (else, branch 27 loc 1) → edge check true (branch 28 loc 0).
        installMock({ kind: "ok", bytes: BIN_BYTES }, { kind: "ok", json: meta("curl-impersonate", "edge-140") });
        const capture = loadGolden(CHROME);
        expect(capture.source).toBe("edge-140");
    });

    it("falls through to the default return for an unknown profile (branch 28 loc 1)", () => {
        // profile "opera-100" → not chrome/firefox/safari/edge → safari else
        // (branch 27 loc 1) → edge else (branch 28 loc 1) → return "chrome-140".
        installMock({ kind: "ok", bytes: BIN_BYTES }, { kind: "ok", json: meta("curl-impersonate", "opera-100") });
        const capture = loadGolden(CHROME);
        expect(capture.source).toBe("chrome-140");
    });
});

describe("loadCaptureMeta — catch, non-Error thrown (branch 29)", () => {
    it("wraps a non-Error meta-read throw as `new Error(String(e))`", () => {
        installMock({ kind: "throw", value: Symbol("nope") }, { kind: "throw", value: Symbol("nope") });
        expect(() => loadCaptureMeta(CHROME)).toThrow(TestingError);
        try {
            loadCaptureMeta(CHROME);
            expect.unreachable("should have thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(TestingError);
            expect((e as TestingError).cause).toBeInstanceOf(Error);
        }
    });
});
