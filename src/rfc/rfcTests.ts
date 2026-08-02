/**
 * RFC compliance test suites.
 *
 * Each function runs a focused compliance check and returns a {@link TestResult}.
 * Stubbed until the underlying protocol stacks exist.
 */

import type { TestCaseId, TestResult } from "../types.js";

/** Run the TLS 1.3 (RFC 8446) compliance checks. */
export function runTlsCompliance(
    _id: TestCaseId = ("tls_rfc" as never),
): TestResult {
    void _id;
    throw new Error("not implemented — see PLAN.md");
}

/** Run the HTTP/2 (RFC 9113) compliance checks. */
export function runHttp2Compliance(
    _id: TestCaseId = ("http2_rfc" as never),
): TestResult {
    void _id;
    throw new Error("not implemented — see PLAN.md");
}

/** Run the HTTP/1.1 (RFC 9110) compliance checks. */
export function runHttp1Compliance(
    _id: TestCaseId = ("http1_rfc" as never),
): TestResult {
    void _id;
    throw new Error("not implemented — see PLAN.md");
}
