/**
 * Tests for the ReferenceProviderFacade primary→secondary fallback
 * (src/reference/reference.ts).
 *
 * The existing reference.test.ts covers each provider in isolation; this file
 * exercises the facade's try-primary-then-fall-back logic for both capture()
 * and fingerprint(), plus the createReferenceProvider exhaustiveness guard.
 */

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
    createReferenceFacade,
    createReferenceProvider,
    ReferenceProviderFacade,
    ReferenceError,
    type ReferenceProviderKind,
} from "../src/reference/reference.js";

const here = dirname(fileURLToPath(import.meta.url));
const mockBinary = join(here, "fixtures", "mock-curl-impersonate.sh");
const brokenCommand = "this-binary-does-not-exist-xyz";

describe("ReferenceProviderFacade.capture (fallback)", () => {
    it("uses the primary (mock binary) when it succeeds", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: mockBinary } });
        const capture = await facade.capture("chrome-140", "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
        expect(capture.protocol).toBe("tls");
    });

    it("falls back to the secondary when the primary fails", async () => {
        // Broken primary command → primary throws → secondary (real-browser) serves
        // the in-repo chrome-140 TLS capture.
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        const capture = await facade.capture("chrome-140", "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
        expect(capture.id).toBe("chrome-140/tls/client_hello");
    });

    it("throws ReferenceError when both primary and secondary fail", async () => {
        // Broken primary + a profile the secondary has no capture for.
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        await expect(
            facade.capture("safari-99" as never, "https://example.com"),
        ).rejects.toThrow(ReferenceError);
    });

    it("includes both failure messages in the combined error", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        await expect(
            facade.capture("ie-6" as never, "https://example.com"),
        ).rejects.toThrow(/primary failed.*secondary failed/);
    });
});

describe("ReferenceProviderFacade.fingerprint (fallback)", () => {
    it("uses the primary (mock binary) when it succeeds", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: mockBinary } });
        const fp = await facade.fingerprint("chrome-140");
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
        expect(fp.ja4).toContain("_");
    });

    it("falls back to the secondary when the primary fails", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        const fp = await facade.fingerprint("chrome-140");
        // Secondary derives the fingerprint from the in-repo capture.
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
    });

    it("falls back to the secondary for firefox-128", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        const fp = await facade.fingerprint("firefox-128");
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
    });

    it("throws ReferenceError when both primary and secondary fail", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        await expect(
            facade.fingerprint("safari-99" as never),
        ).rejects.toThrow(ReferenceError);
    });

    it("includes both failure messages in the combined fingerprint error", async () => {
        const facade = new ReferenceProviderFacade({ curl: { command: brokenCommand } });
        await expect(
            facade.fingerprint("ie-6" as never),
        ).rejects.toThrow(/No fingerprint available.*primary failed.*secondary failed/);
    });
});

describe("createReferenceProvider exhaustiveness guard", () => {
    it("throws for an unknown provider kind (assertNever)", () => {
        // Cast to bypass the discriminated union — simulates a future provider
        // kind added without a handler.
        const bogus = { kind: "unknown-future-provider" } as unknown as ReferenceProviderKind;
        expect(() => createReferenceProvider(bogus)).toThrow(/Unexpected value/);
    });
});

describe("ReferenceProviderFacade.availableProfiles", () => {
    it("de-duplicates profiles shared by both providers", () => {
        const facade = new ReferenceProviderFacade();
        const profiles = facade.availableProfiles();
        // chrome-140 is offered by both the curl provider and the capture
        // manifest; it must appear exactly once.
        expect(new Set(profiles.map(String)).size).toBe(profiles.length);
        expect(profiles.map(String)).toContain("chrome-140");
    });
});
