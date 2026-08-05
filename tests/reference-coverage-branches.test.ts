/**
 * Coverage-targeted tests for the remaining branches in src/reference/
 * reference.ts and src/reference/dump.ts below 94%.
 *
 * reference.test.ts + reference-coverage.test.ts cover the providers and the
 * narrowing helpers. This file targets the remaining branches:
 *
 * - reference.ts lines 105-129: the secondary-fallback branches in capture()
 *   and fingerprint(). The primary provider (curl-impersonate) is exercised
 *   with the mock binary (succeeds); to reach the secondary fallback we make
 *   the primary fail by passing a broken command. The facade then falls back
 *   to the real-browser secondary, exercising the `try { primary } catch {
 *   try { secondary } }` structure. We also cover the case where BOTH fail
 *   (ReferenceError thrown).
 * - dump.ts lines 42, 92-108: the `parseDumpOutput` marker-not-found branch
 *   (returns the whole stdout as the body) and the `cipherSuiteName` empty-tag
 *   fallback branch.
 */

import { describe, expect, it } from "vitest";
import {
    createReferenceFacade,
    CurlImpersonateProvider,
    RealBrowserCaptureProvider,
    parseDumpOutput,
    fingerprintFromTlsCapture,
    cipherSuiteName,
    ReferenceError,
} from "../src/reference/reference.js";
import type { CaptureId } from "../src/types.js";
import type { ProfileId } from "@browsercore/profiles";

describe("ReferenceProviderFacade — secondary fallback (reference.ts lines 105-129)", () => {
    it("falls back to the secondary provider when the primary fails", async () => {
        // Primary with a non-existent command → throws → facade catches and
        // falls back to the real-browser secondary. This exercises the outer
        // catch + inner try in capture() (reference.ts lines 105-116).
        const facade = createReferenceFacade({
            curl: { command: "does-not-exist-xyz" },
        });
        const capture = await facade.capture("chrome-140" as CaptureId, "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
    });

    it("falls back to the secondary provider for fingerprint() when the primary fails", async () => {
        const facade = createReferenceFacade({
            curl: { command: "does-not-exist-xyz" },
        });
        const fp = await facade.fingerprint("chrome-140" as CaptureId);
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
    });

    it("uses the secondary's own fingerprint path for a non-TLS capture", async () => {
        // Directly exercise the secondary provider's fingerprint() protocol
        // guard: stub capture() to return an HTTP/2 capture. The secondary's
        // fingerprint() throws ReferenceError with "only supports TLS" — this
        // exercises the protocol !== "tls" branch inside fingerprint() (which
        // the facade's fallback path would surface if the primary failed).
        const provider = new RealBrowserCaptureProvider();
        provider.capture = async () => ({
            id: "firefox-128/http2/settings" as CaptureId,
            source: "firefox-135" as const,
            protocol: "http2" as const,
            bytes: new Uint8Array(),
            description: "HTTP/2 SETTINGS",
        });
        await expect(provider.fingerprint("firefox-128" as CaptureId)).rejects.toThrow(
            /only supports TLS/,
        );
    });
});

describe("CurlImpersonateProvider — fallback to secondary via broken primary", () => {
    it("the secondary provider alone succeeds for chrome-140", async () => {
        const provider = new RealBrowserCaptureProvider();
        const capture = await provider.capture("chrome-140" as CaptureId, "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
    });
});

describe("CurlImpersonateProvider — capture() catch branch (curl-provider.ts line 107)", () => {
    it("throws ReferenceError when the curl-impersonate command fails", async () => {
        // A non-existent command makes execFile reject, exercising the catch
        // branch at curl-provider.ts line 107 that wraps the failure in a
        // ReferenceError. The error message identifies the profile and the
        // underlying cause.
        const provider = new CurlImpersonateProvider({
            command: "does-not-exist-xyz-binary",
        });
        await expect(
            provider.capture("chrome-140" as ProfileId, "https://example.com"),
        ).rejects.toThrow(ReferenceError);
        await expect(
            provider.capture("chrome-140" as ProfileId, "https://example.com"),
        ).rejects.toThrow(/curl-impersonate capture for .* failed/);
    });
});

describe("parseDumpOutput — marker-not-found + odd-length branches (dump.ts)", () => {
    it("parses hex bytes when the traffic marker is absent (whole string is body)", () => {
        // When ">>> traffic <<<" is not found, parseDumpOutput uses the whole
        // stdout as the body. This exercises the `idx === -1` branch (dump.ts
        // line 42).
        const stdout = "16030100200100001c03030303030303";
        const bytes = parseDumpOutput(stdout);
        expect(bytes.length).toBe(16);
        expect(bytes[0]).toBe(0x16);
    });

    it("throws when the hex has odd length", () => {
        expect(() => parseDumpOutput(">>> traffic <<<\nabc\n")).toThrow(/odd-length/);
    });

    it("throws when no hex bytes are present", () => {
        // Use a string with NO hex characters at all → the stripped hex is
        // empty → the `hex.length === 0` branch fires (dump.ts line 47).
        expect(() => parseDumpOutput("zzzz zzzz")).toThrow(/no hex/);
        expect(() => parseDumpOutput("")).toThrow(/no hex/);
    });
});

describe("fingerprintFromTlsCapture — sidecar fallback (dump.ts lines 92-108)", () => {
    it("falls back gracefully when the sidecar meta is missing", async () => {
        // A capture id that does not resolve to a sidecar on disk. The
        // loadCaptureMeta call inside fingerprintFromTlsCapture throws, the
        // catch fires, and the richer fields (alpn, sigAlgs, curves) stay
        // empty while ja3/ja4 are still computed from the valid bytes.
        // Reuse the in-repo chrome-140 TLS bytes so computeJa3/JA4 succeed.
        const { readFileSync } = await import("node:fs");
        const { join } = await import("node:path");
        const validTlsBytes = readFileSync(
            join(import.meta.dirname, "..", "captures", "chrome-140", "tls", "client_hello.bin"),
        );
        const capture = {
            id: "ghost/tls/client_hello" as CaptureId,
            source: "chrome-140" as const,
            protocol: "tls" as const,
            bytes: validTlsBytes,
            description: "no sidecar",
        };
        const fp = fingerprintFromTlsCapture(capture);
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
        expect(fp.ja4).toContain("_");
        // The catch path leaves the richer fields empty.
        expect(fp.alpn).toEqual([]);
        expect(fp.signatureAlgorithms).toEqual([]);
        expect(fp.ellipticCurves).toEqual([]);
    });
});

describe("cipherSuiteName — empty-tag fallback (dump.ts line 108)", () => {
    it("returns 'unknown' for an empty tag (line 108 fallback branch)", () => {
        // ja4Tag="" → split("_")[0]="" → a.length === 0 → returns "unknown".
        // Exercises the `a.length > 0 ? a : "unknown"` false branch (arm 1).
        expect(cipherSuiteName("")).toBe("unknown");
    });

    it("returns the JA4_a segment for a tag with underscore (line 108 true branch)", () => {
        // ja4Tag="abc_def" → split("_")[0]="abc" → a.length > 0 → returns "abc".
        // Exercises the `a.length > 0 ? a : "unknown"` true branch (arm 0).
        expect(cipherSuiteName("abc_def")).toBe("abc");
    });
});
