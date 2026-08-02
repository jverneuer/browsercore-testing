/**
 * Benchmark suite for protocol operations.
 *
 * Typed stubs for now — real benchmarks require live servers and the
 * underlying protocol stacks.
 */

import type { BenchStats } from "../types.js";

/** Benchmark a single TLS handshake over `iterations` runs. */
export function benchmarkTlsHandshake(
    _iterations: number,
    _options?: { host?: string; port?: number; profile?: string },
): BenchStats {
    void _iterations;
    void _options;
    throw new Error("not implemented — see PLAN.md");
}

/** Benchmark an HTTP/2 request round-trip over `iterations` runs. */
export function benchmarkHttp2Request(
    _iterations: number,
    _options?: { host?: string; port?: number; path?: string; profile?: string },
): BenchStats {
    void _iterations;
    void _options;
    throw new Error("not implemented — see PLAN.md");
}
