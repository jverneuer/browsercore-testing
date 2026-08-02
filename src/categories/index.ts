/**
 * Barrel for the 17 test-category vitest suites (docs/TEST-SUITE.md).
 *
 * Each module exports its category id constant(s) alongside the `describe`
 * block, so consumers can reference stable ids without magic strings.
 */

export { CATEGORY_ID as tcpTransport } from "./transport.js";
export { CATEGORY_ID_TLS as tlsSerialization, CATEGORY_ID_PROFILE as browserProfileComparison, CATEGORY_ID_FINGERPRINT as tlsFingerprint } from "./tls.js";
export { CATEGORY_ID_HTTP1 as http1, CATEGORY_ID_HTTP2 as http2, CATEGORY_ID_HEADERS as headerProfiles } from "./http.js";
export { CATEGORY_ID as cookieBehavior } from "./cookies.js";
export { CATEGORY_ID as compression } from "./compression.js";
export { CATEGORY_ID as redirectHandling } from "./redirects.js";
export { CATEGORY_ID_SESSION as sessionResumption, CATEGORY_ID_REUSE as connectionReuse } from "./session.js";
export { CATEGORY_ID as errorHandling } from "./errors.js";
export { CATEGORY_ID_CAPTURE as packetCaptureComparison, CATEGORY_ID_REALWORLD as realWorldCompatibility } from "./capture.js";
export { CATEGORY_ID_REGRESSION as regression, CATEGORY_ID_BENCHMARKS as performanceBenchmarks } from "./regression.js";
