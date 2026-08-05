/**
 * Coverage-targeted tests for the gaps holding src/bench/bench.ts below 94%.
 *
 * bench.test.ts covers the happy path. The remaining uncovered branch is the
 * empty-array early-return in percentile() (line 62): `if (sorted.length === 0)
 * return 0`. This branch is unreachable through benchmarkTlsHandshake /
 * benchmarkHttp2Request because `measure()` always produces at least one timing
 * (iterations >= 1). We exercise it directly by importing the benchmark
 * functions and calling them with iterations=0, which Math.max(1, 0) clamps to
 * 1 — so instead we verify the branch is genuinely dead code by confirming
 * the benchmarks always return finite stats, and we cover the percentile
 * empty-array branch by testing the observable behavior: a single-iteration
 * benchmark produces p50 === p95 === p99 (all equal to the one sample).
 */

import { describe, expect, it } from "vitest";
import { benchmarkTlsHandshake, benchmarkHttp2Request } from "../src/index.js";

describe("benchmarkTlsHandshake — percentile edge cases", () => {
    it("produces equal percentiles for a single iteration (one sample)", () => {
        // With one sample, p50 === p95 === p99 === that sample. This exercises
        // the percentile() function with a 1-element sorted array — the branch
        // where Math.ceil(p * sorted.length) - 1 === 0 for all p.
        const stats = benchmarkTlsHandshake(1);
        expect(stats.iterations).toBe(1);
        expect(Number.isFinite(stats.p50)).toBe(true);
        expect(stats.p50).toBe(stats.p95);
        expect(stats.p95).toBe(stats.p99);
    });

    it("clamps iterations to >= 1 even when 0 is passed", () => {
        // Math.max(1, 0) === 1. The benchmark must not throw and must report
        // a single iteration.
        const stats = benchmarkTlsHandshake(0);
        expect(stats.iterations).toBe(1);
        expect(Number.isFinite(stats.avgMs)).toBe(true);
    });

    it("returns sorted percentiles for a small iteration count", () => {
        const stats = benchmarkTlsHandshake(5);
        expect(stats.iterations).toBe(5);
        expect(stats.p50).toBeLessThanOrEqual(stats.p95);
        expect(stats.p95).toBeLessThanOrEqual(stats.p99);
    });
});

describe("benchmarkHttp2Request — percentile edge cases", () => {
    it("produces equal percentiles for a single iteration", () => {
        const stats = benchmarkHttp2Request(1);
        expect(stats.iterations).toBe(1);
        expect(stats.p50).toBe(stats.p95);
        expect(stats.p95).toBe(stats.p99);
    });

    it("clamps iterations to >= 1", () => {
        const stats = benchmarkHttp2Request(0);
        expect(stats.iterations).toBe(1);
    });
});

describe("percentile — empty-array branch (bench.ts line 62)", () => {
    it("returns zero percentiles when the timings array is empty", () => {
        // Math.max(1, NaN) === NaN. The for loop in measure() does not execute
        // when iterations is NaN (0 < NaN is false), so measure() returns an
        // empty array. percentile() then takes its `sorted.length === 0`
        // early-return branch (bench.ts line 62) and returns 0 for all three
        // percentiles.
        const stats = benchmarkTlsHandshake(NaN);
        expect(stats.p50).toBe(0);
        expect(stats.p95).toBe(0);
        expect(stats.p99).toBe(0);
    });
});
