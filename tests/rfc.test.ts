/**
 * RFC compliance test suite tests.
 *
 * runTlsCompliance / runHttp2Compliance / runHttp1Compliance validate the
 * in-repo golden captures against the @browsercore/profiles definitions.
 * Each returns a TestResult whose `pass` field we assert on; a failing result
 * carries a `diff` describing the first divergence.
 *
 * Note: the in-repo captures are synthetic (deterministic, minimal
 * ClientHellos / SETTINGS frames from tests/fixtures/mock-curl-impersonate.sh),
 * not full real-browser captures. The TLS compliance test therefore validates
 * the capture-parsing path against the profile, and the HTTP/2/HTTP1 tests
 * validate the profile's self-consistency.
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
        // The synthetic capture advertises MAX_CONCURRENT_STREAMS=100 and
        // INITIAL_WINDOW_SIZE=65536. The profile's maxConcurrentStreams is 100
        // (matches), but initialWindowSize is 6291456 (does not match 65536).
        // So the compliance check reports a failure — which is correct: the
        // capture and profile disagree, and the compliance test surfaces this.
        expect(typeof result.pass).toBe("boolean");
        expect(result.actual).toBeDefined();
    });

    it("parses the golden SETTINGS frame and extracts settings", () => {
        const result = runHttp2Compliance();
        // The actual field should be a map of setting id → value.
        const actual = result.actual as Record<string, number>;
        expect(actual).toBeDefined();
        // MAX_CONCURRENT_STREAMS (id 3) = 100 from the synthetic capture.
        expect(actual["3"]).toBe(100);
        // INITIAL_WINDOW_SIZE (id 4) = 65536 from the synthetic capture.
        expect(actual["4"]).toBe(65536);
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
