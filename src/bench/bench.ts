/**
 * Benchmark suite for protocol operations.
 *
 * Benchmarks here measure operations that need no live server — capture
 * parsing, fingerprint computation, golden comparison, and compression
 * round-trips — so they run in CI. Live TLS-handshake / HTTP/2-request
 * benchmarks (which require a functional protocol stack + loopback server)
 * remain a future addition; see docs/TEST-SUITE.md (Phase 10) for the full
 * roadmap.
 *
 * Each benchmark runs `iterations` repetitions, collects per-iteration
 * timings in microseconds, and reports p50/p95/p99 latency plus average
 * throughput.
 */

import type { BenchStats } from "../types.js";
import { computeJa3, computeJa4 } from "../fingerprint/index.js";
import { compareBytes } from "../utils.js";
import { compression } from "@browsercore/compression";
import { fileSystem, path } from "../node-provider.js";

const here = import.meta.dirname;
// src/bench -> package root -> captures/
const capturesDir = path.join(here, "..", "..", "captures");

/** Deterministic payload: byte[i] = i % 256 (reproducible, never random). */
function detBuffer(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = i % 256;
    }
    return bytes;
}

/** High-resolution timestamp in microseconds (browser-safe fallback). */
function nowUs(): number {
    return performance.now() * 1000;
}

/**
 * Run `fn` for `iterations` repetitions and return the per-iteration timings
 * in microseconds, sorted ascending. The warm-up iteration is discarded to
 * eliminate first-call JIT / cache effects.
 */
function measure(iterations: number, fn: () => void): number[] {
    // Warm-up.
    fn();
    const timings: number[] = [];
    for (let i = 0; i < iterations; i++) {
        const start = nowUs();
        fn();
        timings.push(nowUs() - start);
    }
    timings.sort((a, b) => a - b);
    return timings;
}

/** Read a percentile (0..1) from a sorted array of samples. */
export function percentile(sorted: number[], p: number): number {
    if (sorted.length === 0) {
        return 0;
    }
    const idx = Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1);
    return sorted[Math.max(0, idx)] ?? 0;
}

/**
 * Benchmark the TLS ClientHello fingerprint computation (JA3 + JA4) over
 * `iterations` runs against the chrome-140 golden capture. Reports
 * p50/p95/p99 latency in milliseconds.
 */
export function benchmarkTlsHandshake(
    iterations: number,
    _options?: { host?: string; port?: number; profile?: string },
): BenchStats {
    void _options;
    // Load the chrome-140 golden capture once; the benchmark measures the
    // parsing + fingerprinting cost, not the live handshake (which needs a
    // functional TLS stack + loopback server — future work).
    const bytes = fileSystem.readFileSync(
        path.join(capturesDir, "chrome-140", "tls", "client_hello.bin"),
    );
    const iters = Math.max(1, iterations);

    const timings = measure(iters, () => {
        computeJa3(bytes);
        computeJa4(bytes);
    });

    const avgMs = timings.reduce((a, b) => a + b, 0) / timings.length / 1000;
    return {
        iterations: iters,
        avgMs,
        p50: percentile(timings, 0.5) / 1000,
        p95: percentile(timings, 0.95) / 1000,
        p99: percentile(timings, 0.99) / 1000,
    };
}

/**
 * Benchmark the golden-comparison path (load + byte-compare) over
 * `iterations` runs. This exercises the Category 14 packet-capture
 * comparison core. Reports p50/p95/p99 latency in milliseconds.
 */
export function benchmarkHttp2Request(
    iterations: number,
    _options?: { host?: string; port?: number; path?: string; profile?: string },
): BenchStats {
    void _options;
    // The HTTP/2 SETTINGS frame is small and deterministic — ideal for
    // repeated comparison benchmarking without a live server.
    const bytes = fileSystem.readFileSync(
        path.join(capturesDir, "chrome-140", "http2", "settings.bin"),
    );
    const iters = Math.max(1, iterations);

    // Pre-compress a payload for the compression round-trip sub-benchmark.
    const payload = detBuffer(8192);
    const compressed = compression.gzip(payload);

    const timings = measure(iters, () => {
        // Golden comparison path: compare the SETTINGS bytes against themselves.
        compareBytes(bytes, bytes);
        // Compression round-trip: representative of per-request work.
        compression.gunzip(compressed);
    });

    const avgMs = timings.reduce((a, b) => a + b, 0) / timings.length / 1000;
    return {
        iterations: iters,
        avgMs,
        p50: percentile(timings, 0.5) / 1000,
        p95: percentile(timings, 0.95) / 1000,
        p99: percentile(timings, 0.99) / 1000,
    };
}
