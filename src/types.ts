/**
 * Domain types for @browsercore/testing.
 *
 * Protocol verification: RFC compliance tests, browser golden packet captures,
 * integration tests, and benchmarking. Compares generated packets against
 * captures from real browsers.
 */

import type { ProfileId } from "@browsercore/profiles";

/** Branded test-case identifier. */
export type TestCaseId = string & { __brand: "TestCaseId" };

/** Branded golden-capture identifier. */
export type CaptureId = string & { __brand: "CaptureId" };

/** Known browser capture sources. */
export type CaptureSource =
    | "chrome-140"
    | "firefox-135"
    | "safari-18"
    | "edge-140";

/** Which protocol layer a capture records. */
export type CaptureProtocol = "tls" | "http2" | "http1" | "tcp";

/** A single runnable test case. */
export interface TestCase {
    readonly id: TestCaseId;
    readonly name: string;
    readonly description: string;
    run(): Promise<TestResult>;
}

/** Outcome of running a single {@link TestCase}. */
export interface TestResult {
    readonly id: TestCaseId;
    readonly pass: boolean;
    /** Actual bytes / value produced. */
    readonly actual: unknown;
    /** Expected bytes / value. */
    readonly expected: unknown;
    /** Human-readable diff when `pass === false`. */
    readonly diff?: string;
}

/** A golden packet capture recorded from a real browser. */
export interface GoldenCapture {
    readonly id: CaptureId;
    readonly source: CaptureSource;
    readonly protocol: CaptureProtocol;
    /** Raw bytes as seen on the wire. */
    readonly bytes: Uint8Array;
    readonly description: string;
}

/** Result of comparing actual bytes against a golden capture. */
export interface ComparisonResult {
    readonly matches: boolean;
    /** First byte index where actual diverges from expected, if any. */
    readonly divergenceByteIndex: number | undefined;
    readonly message: string;
}

/** Summary statistics for a benchmark run. */
export interface BenchStats {
    readonly iterations: number;
    readonly avgMs: number;
    readonly p50: number;
    readonly p95: number;
    readonly p99: number;
}

/**
 * The 17 test categories from docs/TEST-SUITE.md.
 *
 * Defined as a `const` object so the id set is the single source of truth and
 * `TestCategoryId` is derived from it — never a bare string (see
 * CODING_STANDARDS.md §17 "No magic strings").
 */
export const TestCategory = {
    TcpTransport: "tcp-transport",
    TlsSerialization: "tls-serialization",
    BrowserProfileComparison: "browser-profile-comparison",
    TlsFingerprint: "tls-fingerprint",
    Http1: "http1",
    Http2: "http2",
    HeaderProfiles: "header-profiles",
    CookieBehavior: "cookie-behavior",
    Compression: "compression",
    RedirectHandling: "redirect-handling",
    SessionResumption: "session-resumption",
    ConnectionReuse: "connection-reuse",
    ErrorHandling: "error-handling",
    PacketCaptureComparison: "packet-capture-comparison",
    RealWorldCompatibility: "real-world-compatibility",
    Regression: "regression",
    PerformanceBenchmarks: "performance-benchmarks",
} as const;

/** One of the 17 known test-category ids. */
export type TestCategoryId = (typeof TestCategory)[keyof typeof TestCategory];

/** Lifecycle status of a spec test case in the plan. */
export type TestStatus = "planned" | "implemented" | "skipped";

/**
 * A single test case as recorded in the spec plan.
 *
 * Distinct from the runnable {@link TestCase} interface (which carries a
 * `run()` method); this is a static plan/record entry.
 */
export interface SpecTestCase {
    readonly id: TestCaseId;
    readonly category: TestCategoryId;
    readonly name: string;
    readonly description: string;
    readonly status: TestStatus;
}

/** A recorded run of spec test cases plus their outcomes. */
export interface TestRun {
    readonly id: string;
    readonly timestamp: string;
    readonly cases: readonly SpecTestCase[];
}

/**
 * A byte range within a capture that is intentionally randomized by the
 * protocol spec and so MUST be masked before golden comparison (Cat 14).
 */
export interface RandomizedField {
    readonly byteOffset: number;
    readonly length: number;
    readonly reason: "ephemeral_key" | "nonce" | "grease" | "random";
}

/** Metadata describing a stored golden capture (sidecar to its `.bin`). */
export interface CaptureMeta {
    readonly source: "curl-impersonate" | "real-browser";
    readonly profile: ProfileId;
    readonly protocol: CaptureProtocol;
    readonly record: "client_hello" | "settings" | "headers" | "server_hello";
    readonly description: string;
    readonly randomizedFields: readonly RandomizedField[];
    readonly createdAt: string;
}

/**
 * Result of a byte comparison that supports an ignore-list of randomized
 * ranges. Extends {@link ComparisonResult} with the ranges that were masked.
 */
export interface ComparisonResultWithIgnore {
    readonly matches: boolean;
    readonly divergenceByteIndex: number | undefined;
    readonly message: string;
    readonly maskedRanges: readonly RandomizedField[];
}
