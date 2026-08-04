/**
 * Golden byte-matching tests — TLS / HTTP/2 wire bytes vs. golden captures.
 *
 * These tests exercise the core Category 2/3/6 infrastructure: loading
 * golden captures, parsing them, computing fingerprints, and comparing bytes
 * with the ignore-list of randomized fields. The in-repo captures are
 * synthetic (see tests/fixtures/mock-curl-impersonate.sh) — they are
 * deterministic, minimal ClientHellos / SETTINGS frames used for offline
 * testing, not full real-browser captures. So these tests verify the
 * infrastructure works correctly; byte-for-byte profile validation against
 * real captures is covered by the RFC compliance suites (which use the
 * profile data as the source of truth).
 */

import { describe, expect, it } from "vitest";
import { loadGolden, compareAgainstGoldenWithIgnore } from "../src/golden/golden.js";
import { parseClientHello, computeJa3, computeJa4 } from "../src/fingerprint/index.js";
import type { CaptureId } from "../src/types.js";

const CHROME_TLS = "chrome-140/tls/client_hello" as CaptureId;
const CHROME_HTTP2 = "chrome-140/http2/settings" as CaptureId;
const FIREFOX_TLS = "firefox-128/tls/client_hello" as CaptureId;

describe("TLS golden byte-match — compareAgainstGoldenWithIgnore", () => {
    it("chrome-140 ClientHello byte-matches itself (masked ranges excluded)", () => {
        const capture = loadGolden(CHROME_TLS);
        // A capture compared against itself MUST match — even with randomized
        // fields — because the ignore-list is derived from the same meta.
        const result = compareAgainstGoldenWithIgnore(capture.bytes, CHROME_TLS);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges.length).toBeGreaterThan(0);
    });

    it("firefox-128 ClientHello byte-matches itself (masked ranges excluded)", () => {
        const capture = loadGolden(FIREFOX_TLS);
        const result = compareAgainstGoldenWithIgnore(capture.bytes, FIREFOX_TLS);
        expect(result.matches).toBe(true);
    });

    it("detects a divergence outside the masked ranges", () => {
        const capture = loadGolden(CHROME_TLS);
        const mutated = new Uint8Array(capture.bytes);
        // Byte 4 is the TLS record version (0x03) — not in any masked range.
        mutated[4] = mutated[4]! ^ 0xff;
        expect(() => compareAgainstGoldenWithIgnore(mutated, CHROME_TLS)).toThrow();
    });
});

describe("TLS golden parse — chrome-140", () => {
    it("parses the golden ClientHello into JA3/JA4 segments", () => {
        const capture = loadGolden(CHROME_TLS);
        const ja3 = computeJa3(capture.bytes);
        const ja4 = computeJa4(capture.bytes);

        // JA3 is a 32-char MD5 hex string.
        expect(ja3).toMatch(/^[0-9a-f]{32}$/);
        // JA4 tag has three underscores separating the four parts.
        expect(ja4.split("_")).toHaveLength(4);
    });

    it("parses the cipher suites from the golden ClientHello", () => {
        const capture = loadGolden(CHROME_TLS);
        const parsed = parseClientHello(capture.bytes);

        // The synthetic capture has 2 cipher suites (TLS_AES_128_GCM_SHA256
        // and TLS_AES_256_GCM_SHA384). Verify they parse correctly.
        const ciphers = parsed.ciphers.split("-").filter((s) => s.length > 0).map((s) => parseInt(s, 10));
        expect(ciphers.length).toBe(2);
        expect(ciphers[0]).toBe(0x1301); // TLS_AES_128_GCM_SHA256
        expect(ciphers[1]).toBe(0x1302); // TLS_AES_256_GCM_SHA384
    });

    it("parses the extensions from the golden ClientHello", () => {
        const capture = loadGolden(CHROME_TLS);
        const parsed = parseClientHello(capture.bytes);

        // The synthetic capture has 4 extensions: SNI(0), supported_groups(10),
        // ec_point_formats(11), ALPN(16).
        const exts = parsed.extensions
            .split("-")
            .filter((s) => s.length > 0)
            .map((s) => parseInt(s, 10));
        expect(exts).toContain(0); // SNI
        expect(exts).toContain(10); // supported_groups
        expect(exts).toContain(11); // ec_point_formats
        expect(exts).toContain(16); // ALPN
    });

    it("parses supported groups from the golden ClientHello", () => {
        const capture = loadGolden(CHROME_TLS);
        const parsed = parseClientHello(capture.bytes);

        // The synthetic capture advertises x25519 (0x001d) in supported_groups.
        const groups = parsed.supportedGroups
            .split("-")
            .filter((s) => s.length > 0)
            .map((s) => parseInt(s, 10));
        expect(groups).toContain(0x001d); // x25519
    });
});

describe("TLS golden parse — firefox-128", () => {
    it("parses the golden ClientHello and computes JA3/JA4", () => {
        const capture = loadGolden(FIREFOX_TLS);
        const ja3 = computeJa3(capture.bytes);
        const ja4 = computeJa4(capture.bytes);

        expect(ja3).toMatch(/^[0-9a-f]{32}$/);
        expect(ja4.split("_")).toHaveLength(4);
    });

    it("parses the cipher suites from the golden ClientHello", () => {
        const capture = loadGolden(FIREFOX_TLS);
        const parsed = parseClientHello(capture.bytes);

        // The synthetic capture has 2 cipher suites.
        const ciphers = parsed.ciphers.split("-").filter((s) => s.length > 0).map((s) => parseInt(s, 10));
        expect(ciphers.length).toBe(2);
    });
});

describe("HTTP/2 golden byte-match — chrome-140", () => {
    it("SETTINGS frame byte-matches itself (no randomized fields)", () => {
        const capture = loadGolden(CHROME_HTTP2);
        // HTTP/2 SETTINGS are deterministic — no ignore-list needed.
        const result = compareAgainstGoldenWithIgnore(capture.bytes, CHROME_HTTP2);
        expect(result.matches).toBe(true);
        expect(result.maskedRanges).toHaveLength(0);
    });

    it("parses SETTINGS frame and verifies frame type", () => {
        const capture = loadGolden(CHROME_HTTP2);

        // HTTP/2 frame header: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream id.
        const frameType = capture.bytes[3];
        expect(frameType).toBe(0x4); // SETTINGS

        const payload = capture.bytes.slice(9);
        // Each setting is 6 bytes: 2-byte id + 4-byte value.
        const settings = new Map<number, number>();
        for (let i = 0; i + 5 < payload.length; i += 6) {
            const id = (payload[i]! << 8) | payload[i + 1]!;
            const value =
                (payload[i + 2]! << 24) | (payload[i + 3]! << 16) | (payload[i + 4]! << 8) | payload[i + 5]!;
            settings.set(id, value >>> 0);
        }

        // The synthetic capture advertises MAX_CONCURRENT_STREAMS (id 3) = 100
        // and INITIAL_WINDOW_SIZE (id 4) = 65536.
        expect(settings.get(3)).toBe(100); // MAX_CONCURRENT_STREAMS
        expect(settings.get(4)).toBe(65536); // INITIAL_WINDOW_SIZE
    });
});
