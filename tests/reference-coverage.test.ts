/**
 * Coverage-targeted tests for the gaps holding src/reference/reference.ts and
 * src/index.ts below 94%.
 *
 * reference.test.ts + reference-facade.test.ts cover the providers in isolation
 * and the facade fallback. This file targets the remaining branches:
 *
 * - reference.ts lines 176, 193: the `toCurlOptions` / `toBrowserOptions`
 *   narrowing helpers inside `createReferenceProvider`. They are only reached
 *   when options carrying `command` (curl) or `capturesDir` (browser) are
 *   passed — the existing bare-kind calls pass no options.
 * - index.ts lines 49-50: the `loadCaptures()` lazy manifest loader, which no
 *   existing test invokes (it is deliberately NOT eagerly evaluated).
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
    createReferenceProvider,
    CurlImpersonateProvider,
    RealBrowserCaptureProvider,
} from "../src/reference/reference.js";
import { loadCaptures } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const mockBinary = join(here, "fixtures", "mock-curl-impersonate.sh");

describe("createReferenceProvider — narrowing helpers with options", () => {
    it("toCurlOptions: constructs a curl provider when command is provided", () => {
        // Passing { command } exercises the `options.extraArgs === undefined`
        // branch (reference.ts line 175) — extraArgs is omitted, so the narrowed
        // result carries only `command`.
        const provider = createReferenceProvider(
            { kind: "curl-impersonate" },
            { command: mockBinary },
        );
        expect(provider).toBeInstanceOf(CurlImpersonateProvider);
        expect(provider.kind.kind).toBe("curl-impersonate");
    });

    it("toCurlOptions: forwards extraArgs when provided", () => {
        // Passing extraArgs exercises the `options.extraArgs !== undefined`
        // branch (reference.ts line 176).
        const provider = createReferenceProvider(
            { kind: "curl-impersonate" },
            { command: mockBinary, extraArgs: ["--silent"] },
        );
        expect(provider).toBeInstanceOf(CurlImpersonateProvider);
    });

    it("toBrowserOptions: constructs a browser provider when capturesDir is provided", () => {
        // Passing { capturesDir } exercises the browser-options narrowing
        // branch (reference.ts line 193). Point at the in-repo captures dir so
        // the provider can discover the chrome-140 capture.
        const capturesDir = join(here, "..", "captures");
        const provider = createReferenceProvider(
            { kind: "real-browser" },
            { capturesDir },
        );
        expect(provider).toBeInstanceOf(RealBrowserCaptureProvider);
        expect(provider.kind.kind).toBe("real-browser");
    });

    it("returns undefined options (bare kind, no options) without throwing", () => {
        // No options → toCurlOptions returns undefined → provider uses its
        // default command. Confirms the `options === undefined` early-return
        // branch does not throw.
        const provider = createReferenceProvider({ kind: "curl-impersonate" });
        expect(provider.kind.kind).toBe("curl-impersonate");
    });
});

describe("loadCaptures — lazy manifest loader (src/index.ts)", () => {
    it("loads the in-repo capture manifest lazily", async () => {
        // loadCaptures() is the lazy entry point — it must not be eagerly
        // evaluated at import time (so consumers that don't need captures pay
        // no read cost). Invoking it returns the manifest entries.
        const entries = await loadCaptures();
        expect(entries.length).toBeGreaterThan(0);
        // The manifest registers chrome-140 TLS + HTTP/2 and firefox-128 TLS.
        const ids = entries.map((e) => e.path);
        expect(ids).toContain("chrome-140/tls/client_hello.bin");
        expect(ids).toContain("firefox-128/tls/client_hello.bin");
    });

    it("returns entries with parsed meta and raw bytes", async () => {
        const entries = await loadCaptures();
        const chromeTls = entries.find((e) => e.path === "chrome-140/tls/client_hello.bin");
        expect(chromeTls).toBeDefined();
        expect(chromeTls!.meta.profile).toBe("chrome-140");
        expect(chromeTls!.meta.protocol).toBe("tls");
        expect(chromeTls!.bytes.length).toBeGreaterThan(0);
    });
});
