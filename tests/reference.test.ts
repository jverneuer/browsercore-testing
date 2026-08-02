/**
 * Real tests for the pluggable layered reference provider
 * (src/reference/reference.ts).
 *
 * The curl-impersonate PRIMARY provider is exercised against the deterministic
 * mock fixture in tests/fixtures/mock-curl-impersonate.sh; the real-browser
 * SECONDARY provider is exercised against the in-repo capture manifest.
 */

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
    createReferenceProvider,
    createReferenceFacade,
    CurlImpersonateProvider,
    RealBrowserCaptureProvider,
    parseDumpOutput,
    fingerprintFromTlsCapture,
    cipherSuiteName,
} from "../src/reference/reference.js";
import { ReferenceError } from "../src/reference/reference.js";
import type { CaptureId } from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const mockBinary = join(here, "fixtures", "mock-curl-impersonate.sh");

// Valid record-wrapped TLS 1.3 ClientHello bytes (with SNI/groups/EC/ALPN) read
// from the in-repo chrome-140 capture. Used wherever a test needs parseable
// ClientHello bytes without depending on the curl-impersonate mock output.
const validClientHelloBytes = readFileSync(
    join(here, "..", "captures", "chrome-140", "tls", "client_hello.bin"),
);

describe("createReferenceProvider", () => {
    it("constructs a curl-impersonate provider", () => {
        const provider = createReferenceProvider({ kind: "curl-impersonate" });
        expect(provider.kind.kind).toBe("curl-impersonate");
    });

    it("constructs a real-browser provider", () => {
        const provider = createReferenceProvider({ kind: "real-browser" });
        expect(provider.kind.kind).toBe("real-browser");
    });
});

describe("createReferenceFacade", () => {
    it("wraps both providers and exposes the node oracle", () => {
        const facade = createReferenceFacade();
        expect(facade.kind.kind).toBe("curl-impersonate");
        expect(facade.nodeOracle).toBeDefined();
        // Union of both providers' profiles, de-duplicated.
        const profiles = facade.availableProfiles();
        expect(profiles.length).toBeGreaterThan(0);
        expect(new Set(profiles.map(String)).size).toBe(profiles.length);
    });
});

describe("CurlImpersonateProvider (mock binary)", () => {
    const provider = new CurlImpersonateProvider({ command: mockBinary });

    it("captures deterministic bytes from the mock dump", async () => {
        const capture = await provider.capture("chrome-140", "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
        expect(capture.protocol).toBe("tls");
        // Mock emits a valid 96-byte record-wrapped TLS 1.3 ClientHello.
        expect(capture.bytes.length).toBe(96);
    });

    it("derives a fingerprint with JA3/JA4 from the mock capture", async () => {
        const fp = await provider.fingerprint("chrome-140");
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
        expect(fp.ja4).toContain("_"); // canonical tag has three underscores
        // protocolVersion is ja4.tag.slice(5,7): SNI flag + leading version digit.
        expect(fp.protocolVersion).toBe("d1");
    });

    it("throws ReferenceError when the binary is missing", async () => {
        const broken = new CurlImpersonateProvider({ command: "does-not-exist-xyz" });
        await expect(broken.capture("chrome-140", "https://example.com")).rejects.toThrow(
            ReferenceError,
        );
    });
});

describe("RealBrowserCaptureProvider", () => {
    const provider = new RealBrowserCaptureProvider();

    it("captures from the in-repo manifest", async () => {
        const capture = await provider.capture("chrome-140", "https://example.com");
        expect(capture.bytes.length).toBeGreaterThan(0);
        expect(capture.id).toBe("chrome-140/tls/client_hello");
    });

    it("throws ReferenceError for an unknown profile", async () => {
        await expect(
            provider.capture("safari-99" as CaptureId, "https://example.com"),
        ).rejects.toThrow(ReferenceError);
    });

    it("derives a fingerprint for a TLS capture", async () => {
        const fp = await provider.fingerprint("chrome-140");
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
    });

    it("rejects fingerprinting a non-TLS capture", async () => {
        // The in-repo manifest only records TLS captures, so the protocol guard
        // is exercised by stubbing capture() to return an HTTP/2 capture.
        const stubbed = new RealBrowserCaptureProvider();
        stubbed.capture = async () => ({
            id: "firefox-128/http2/settings" as CaptureId,
            source: "firefox-135" as const,
            protocol: "http2" as const,
            bytes: new Uint8Array(),
            description: "HTTP/2 SETTINGS",
        });
        await expect(stubbed.fingerprint("firefox-128" as CaptureId)).rejects.toThrow(
            /only supports TLS/,
        );
    });
});

describe("profileToSource (via capture source tag)", () => {
    const provider = new CurlImpersonateProvider({ command: mockBinary });

    it("maps chrome to chrome-140", async () => {
        const capture = await provider.capture("chrome-140", "https://example.com");
        expect(capture.source).toBe("chrome-140");
    });

    it("maps firefox to firefox-135", async () => {
        const capture = await provider.capture("firefox-128", "https://example.com");
        expect(capture.source).toBe("firefox-135");
    });

    it("maps safari to safari-18", async () => {
        const capture = await provider.capture("safari-18", "https://example.com");
        expect(capture.source).toBe("safari-18");
    });

    it("maps edge to edge-140", async () => {
        const capture = await provider.capture("edge-140", "https://example.com");
        expect(capture.source).toBe("edge-140");
    });
});

describe("parseDumpOutput", () => {
    it("parses hex bytes after the traffic marker", () => {
        const stdout = ">>> traffic <<<\n16030100200100001c03030303030303\n";
        const bytes = parseDumpOutput(stdout);
        expect(bytes.length).toBe(16);
        expect(bytes[0]).toBe(0x16);
    });

    it("throws when no hex bytes follow the marker", () => {
        expect(() => parseDumpOutput(">>> traffic <<<\n   \n\t\n")).toThrow(
            /no hex bytes/,
        );
    });

    it("throws on odd-length hex", () => {
        expect(() => parseDumpOutput(">>> traffic <<<\nabc\n")).toThrow(/odd-length hex/);
    });
});

describe("fingerprintFromTlsCapture", () => {
    it("computes a TLS fingerprint and reads the sidecar when present", () => {
        const capture = {
            id: "chrome-140/tls/client_hello" as CaptureId,
            source: "chrome-140" as const,
            protocol: "tls" as const,
            // Valid record-wrapped TLS 1.3 ClientHello (SNI/groups/EC/ALPN).
            bytes: validClientHelloBytes,
            description: "test",
        };
        const fp = fingerprintFromTlsCapture(capture);
        expect(fp.ja3).toMatch(/^[0-9a-f]{32}$/);
        expect(fp.ja4).toContain("_");
    });

    it("falls back gracefully when the sidecar is missing", () => {
        const capture = {
            id: "ghost/tls/client_hello" as CaptureId,
            source: "chrome-140" as const,
            protocol: "tls" as const,
            bytes: validClientHelloBytes,
            description: "no sidecar",
        };
        const fp = fingerprintFromTlsCapture(capture);
        expect(fp.alpn).toEqual([]);
        expect(fp.signatureAlgorithms).toEqual([]);
        expect(fp.ellipticCurves).toEqual([]);
    });
});

describe("cipherSuiteName", () => {
    it("returns the JA4_a segment of a tag", () => {
        expect(cipherSuiteName("t13d1516h2_8f5862453f0e_abc123def456_7890abcdef12")).toBe(
            "t13d1516h2",
        );
    });

    it("returns 'unknown' for an empty tag", () => {
        expect(cipherSuiteName("")).toBe("unknown");
    });
});
