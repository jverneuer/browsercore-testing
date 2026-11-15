/**
 * RFC compliance test suite tests.
 *
 * runTlsCompliance / runHttp2Compliance / runHttp1Compliance validate the
 * in-repo golden captures against the @browsercore/profiles definitions.
 * Each returns a TestResult whose `pass` field we assert on; a failing result
 * carries a `diff` describing the first divergence.
 *
 * Note: the chrome-140 TLS capture is a synthetic stub (deterministic, minimal
 * ClientHello from tests/fixtures/mock-curl-impersonate.sh), so the TLS
 * compliance test validates the capture-parsing path against the profile.
 * Since 0.2.9 the chrome-140 HTTP/2 SETTINGS golden is REAL capture data
 * (oracle: captures/chrome-131/oracle_capture.reference.json), so the HTTP/2
 * compliance check compares the profile against genuine browser bytes.
 */

import { describe, expect, it } from "vitest";
import { runHttp1Compliance, runHttp2Compliance, runTlsCompliance } from "../src/index.js";

describe("runTlsCompliance", () => {
    it("returns a TestResult with id 'tls_rfc'", () => {
        const result = runTlsCompliance();
        expect(result.id).toBe("tls_rfc");
    });

    it("parses the golden ClientHello without throwing", () => {
        // The synthetic capture is a minimal ClientHello. The compliance
        // function must parse it and return a result (pass or fail) without
        // throwing. The pass/fail outcome depends on whether the synthetic
        // capture matches the profile — which it does not (the capture has
        // 2 cipher suites, the profile has 16). We just assert the call
        // completes and returns a well-formed result.
        const result = runTlsCompliance();
        expect(typeof result.pass).toBe("boolean");
        expect(result.actual).toBeDefined();
        expect(result.expected).toBeDefined();
    });

    it("reports a diff when the capture does not match the profile", () => {
        // The synthetic capture has 2 cipher suites; the chrome-140 profile
        // has 16. The compliance check must report this as a failure with a
        // non-empty diff.
        const result = runTlsCompliance();
        expect(result.pass).toBe(false);
        expect(result.diff).toBeDefined();
        expect(result.diff?.length ?? 0).toBeGreaterThan(0);
    });
});

describe("runHttp2Compliance", () => {
    it("returns a TestResult with id 'http2_rfc'", () => {
        const result = runHttp2Compliance();
        expect(result.id).toBe("http2_rfc");
    });

    it("validates the golden SETTINGS against the chrome-140 profile", () => {
        const result = runHttp2Compliance();
        // Since 0.2.9 the chrome-140 SETTINGS golden is REAL capture data
        // (oracle: captures/chrome-131/oracle_capture.reference.json —
        // 1:65536;2:0;4:6291456;6:262144), matching the chrome-140 profile's
        // declared settings, so the compliance check passes. The old synthetic
        // stub ({3:100, 4:65536}) disagreed with the profile and failed.
        expect(result.pass).toBe(true);
        expect(result.diff).toBeUndefined();
        expect(result.actual).toBeDefined();
    });

    it("parses the golden SETTINGS frame and extracts settings", () => {
        const result = runHttp2Compliance();
        // The actual field should be a map of setting id → value.
        const actual = result.actual as Record<string, number>;
        expect(actual).toBeDefined();
        // Real Chrome SETTINGS values from the oracle capture
        // (chrome-131 reference JSON — identical bytes for chrome-140).
        expect(actual["1"]).toBe(65536); // HEADER_TABLE_SIZE
        expect(actual["2"]).toBe(0); // ENABLE_PUSH
        expect(actual["4"]).toBe(6291456); // INITIAL_WINDOW_SIZE
        expect(actual["6"]).toBe(262144); // MAX_HEADER_LIST_SIZE
        // Real Chrome does not send MAX_CONCURRENT_STREAMS (id 3) — the old
        // synthetic stub did.
        expect(actual["3"]).toBeUndefined();
    });
});

describe("runHttp1Compliance", () => {
    it("verifies the chrome-140 profile headers are RFC 9110 compliant", () => {
        const result = runHttp1Compliance();
        // The chrome-140 profile has a valid Host header (via the "host"
        // entry in headerOrder), lowercase names, no duplicates, and a
        // headerOrder that covers all default headers. It should pass.
        expect(result.pass).toBe(true);
        expect(result.diff).toBeUndefined();
    });

    it("reports the compliance check id", () => {
        const result = runHttp1Compliance();
        expect(result.id).toBe("http1_rfc");
    });
});
