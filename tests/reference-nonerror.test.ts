/**
 * Coverage for the non-Error catch branches in src/reference/reference.ts
 * (lines 105-129).
 *
 * The facade's capture() and fingerprint() wrap caught values that are not
 * Error instances via `value instanceof Error ? value : new Error(String(value))`.
 * The real providers (CurlImpersonateProvider, RealBrowserCaptureProvider) always
 * throw Error subclasses, so these defensive branches are never exercised by
 * the existing tests. We mock both providers to throw non-Error values (a string
 * and a number) to exercise the `: new Error(String(value))` fallback in all
 * four catch sites (capture primary, capture secondary, fingerprint primary,
 * fingerprint secondary).
 */

import { vi, describe, expect, it, afterEach } from "vitest";

const {
    mockPrimaryCapture,
    mockPrimaryFingerprint,
    mockSecondaryCapture,
    mockSecondaryFingerprint,
} = vi.hoisted(() => ({
    mockPrimaryCapture: vi.fn<() => Promise<unknown>>(),
    mockPrimaryFingerprint: vi.fn<() => Promise<unknown>>(),
    mockSecondaryCapture: vi.fn<() => Promise<unknown>>(),
    mockSecondaryFingerprint: vi.fn<() => Promise<unknown>>(),
}));

vi.mock("../src/reference/curl-provider.js", () => ({
    CurlImpersonateProvider: class {
        public readonly kind = { kind: "curl-impersonate" } as const;
        public constructor(_options?: unknown) {}
        public async capture(): Promise<unknown> {
            return mockPrimaryCapture();
        }
        public async fingerprint(): Promise<unknown> {
            return mockPrimaryFingerprint();
        }
        public availableProfiles(): never[] {
            return [];
        }
    },
}));

vi.mock("../src/reference/browser-provider.js", () => ({
    RealBrowserCaptureProvider: class {
        public readonly kind = { kind: "real-browser" } as const;
        public readonly capturesDir = "/tmp";
        public constructor(_options?: unknown) {}
        public async capture(): Promise<unknown> {
            return mockSecondaryCapture();
        }
        public async fingerprint(): Promise<unknown> {
            return mockSecondaryFingerprint();
        }
        public availableProfiles(): never[] {
            return [];
        }
    },
}));

import { createReferenceFacade, ReferenceError } from "../src/reference/reference.js";
import type { ProfileId } from "@browsercore/profiles";

afterEach(() => {
    mockPrimaryCapture.mockReset();
    mockPrimaryFingerprint.mockReset();
    mockSecondaryCapture.mockReset();
    mockSecondaryFingerprint.mockReset();
});

describe("reference.ts — non-Error catch branches (lines 105-129)", () => {
    it("wraps a non-Error primary throw in capture (line 105 else branch)", async () => {
        // Primary throws a string (not an Error) → facade wraps it via
        // `: new Error(String(primaryErr))`. Secondary succeeds so we exercise
        // only the primary non-Error branch.
        mockPrimaryCapture.mockImplementation(() => {
            throw "primary-string-failure";
        });
        mockSecondaryCapture.mockResolvedValue({
            id: "chrome-140/tls/client_hello",
            source: "chrome-140",
            protocol: "tls",
            bytes: new Uint8Array([0x01]),
            description: "mock",
        });
        const facade = createReferenceFacade();
        const capture = await facade.capture("chrome-140" as ProfileId, "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
    });

    it("wraps a non-Error secondary throw in capture (line 110-111 else branch)", async () => {
        // Primary throws an Error (covered path), secondary throws a number
        // (not an Error) → facade wraps it via `: new Error(String(secondaryErr))`.
        // Both fail → ReferenceError is thrown with both messages.
        mockPrimaryCapture.mockImplementation(() => {
            throw new Error("primary-error");
        });
        mockSecondaryCapture.mockImplementation(() => {
            throw 42;
        });
        const facade = createReferenceFacade();
        await expect(
            facade.capture("chrome-140" as ProfileId, "https://example.com"),
        ).rejects.toThrow(ReferenceError);
        await expect(
            facade.capture("chrome-140" as ProfileId, "https://example.com"),
        ).rejects.toThrow(/primary-error/);
        await expect(
            facade.capture("chrome-140" as ProfileId, "https://example.com"),
        ).rejects.toThrow(/42/);
    });

    it("wraps non-Error throws in fingerprint (lines 124, 128-129 else branches)", async () => {
        // Primary throws a string, secondary throws a number → both non-Error
        // branches in fingerprint() are exercised.
        mockPrimaryFingerprint.mockImplementation(() => {
            throw "fp-string-failure";
        });
        mockSecondaryFingerprint.mockImplementation(() => {
            throw 99;
        });
        const facade = createReferenceFacade();
        await expect(
            facade.fingerprint("chrome-140" as ProfileId),
        ).rejects.toThrow(ReferenceError);
        await expect(
            facade.fingerprint("chrome-140" as ProfileId),
        ).rejects.toThrow(/fp-string-failure/);
        await expect(
            facade.fingerprint("chrome-140" as ProfileId),
        ).rejects.toThrow(/99/);
    });
});
