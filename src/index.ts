/**
 * @browsercore/testing — public API surface.
 *
 * Protocol verification: RFC compliance tests, browser golden packet captures,
 * integration tests, and benchmarking.
 */

export { loadGolden, compareAgainstGolden } from "./golden/golden.js";
export { runTlsCompliance, runHttp2Compliance, runHttp1Compliance } from "./rfc/rfcTests.js";
export { benchmarkTlsHandshake, benchmarkHttp2Request } from "./bench/bench.js";

export { GoldenMismatchError, TestingError } from "./errors.js";

export type {
    BenchStats,
    CaptureId,
    CaptureProtocol,
    CaptureSource,
    ComparisonResult,
    GoldenCapture,
    TestCase,
    TestCaseId,
    TestResult,
} from "./types.js";

export { assertNever, bytesToHex, compareBytes, createId } from "./utils.js";

// Test-category model (docs/TEST-SUITE.md) + the 17 vitest suite ids.
export { TestCategory } from "./types.js";
export type { SpecTestCase, TestCategoryId, TestRun, TestStatus } from "./types.js";
export * as categories from "./categories/index.js";

// Randomized-field comparison (Cat 14 core) + capture manifest.
export { compareBytesWithIgnore } from "./utils.js";
export type { CaptureMeta, ComparisonResultWithIgnore, RandomizedField } from "./types.js";
export type { CaptureEntry } from "./captures/manifest.js";

/**
 * Lazily load the golden-capture manifest.
 *
 * The manifest reads each `.bin` from disk, so it is NOT eagerly evaluated at
 * import time (an eager re-export would force every consumer to pay the read
 * cost — and crash if the tarball lacked `captures/`). Call this only when you
 * actually need the captures.
 */
export async function loadCaptures(): Promise<
    readonly import("./captures/manifest.js").CaptureEntry[]
> {
    const manifest = await import("./captures/manifest.js");
    return manifest.captures;
}

// Pluggable layered reference provider.
export {
    createReferenceProvider,
    CurlImpersonateProvider,
    RealBrowserCaptureProvider,
} from "./reference/reference.js";
export type {
    CurlImpersonateOptions,
    Fingerprint,
    RealBrowserOptions,
    ReferenceProvider,
    ReferenceProviderKind,
} from "./reference/reference.js";

// Fingerprint computation (JA3 / JA4) for Cat 4.
export { computeJa3, computeJa4, Ja3ParseError, parseClientHello } from "./fingerprint/index.js";
export type { Ja3Segments } from "./fingerprint/index.js";

// Node.js reference oracle — deterministic comparison target for the primitive
// layers (crypto, dns, zlib, wire format). See src/reference/node-reference.ts.
export {
    nodeCrypto,
    nodeDns,
    nodeZlib,
    nodeHttp,
    toError,
    compareBytesOutcome,
} from "./reference/node-reference.js";
export type { CompareOutcome, HashAlgorithm } from "./reference/node-reference.js";
