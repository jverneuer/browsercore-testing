/**
 * Bench module tests.
 *
 * benchmarkTlsHandshake / benchmarkHttp2Request now measure real operations
 * (fingerprint computation + golden comparison) against the in-repo captures.
 * We assert that the returned BenchStats are well-formed (finite, sorted
 * percentiles) and that the benchmark runs without throwing.
 */

import { describe, expect, it } from "vitest";
import { benchmarkHttp2Request, benchmarkTlsHandshake } from "../src/index.js";

describe("benchmarkTlsHandshake", () => {
    it("returns well-formed BenchStats for fingerprint computation", () => {
        const stats = benchmarkTlsHandshake(50);
        expect(stats.iterations).toBe(50);
        expect(Number.isFinite(stats.avgMs)).toBe(true);
        expect(Number.isFinite(stats.p50)).toBe(true);
        expect(Number.isFinite(stats.p95)).toBe(true);
        expect(Number.isFinite(stats.p99)).toBe(true);
    });

    it("reports sorted percentiles (p50 <= p95 <= p99)", () => {
        const stats = benchmarkTlsHandshake(100);
        expect(stats.p50).toBeLessThanOrEqual(stats.p95);
        expect(stats.p95).toBeLessThanOrEqual(stats.p99);
    });

    it("accepts options without throwing", () => {
        expect(() =>
            benchmarkTlsHandshake(5, { host: "example.com", port: 443, profile: "chrome-140" }),
        ).not.toThrow();
    });

    it("runs with a single iteration", () => {
        const stats = benchmarkTlsHandshake(1);
        expect(stats.iterations).toBe(1);
        expect(Number.isFinite(stats.p50)).toBe(true);
    });
});

describe("benchmarkHttp2Request", () => {
    it("returns well-formed BenchStats for golden comparison + compression", () => {
        const stats = benchmarkHttp2Request(50);
        expect(stats.iterations).toBe(50);
        expect(Number.isFinite(stats.avgMs)).toBe(true);
        expect(Number.isFinite(stats.p50)).toBe(true);
        expect(Number.isFinite(stats.p95)).toBe(true);
        expect(Number.isFinite(stats.p99)).toBe(true);
    });

    it("reports sorted percentiles (p50 <= p95 <= p99)", () => {
        const stats = benchmarkHttp2Request(100);
        expect(stats.p50).toBeLessThanOrEqual(stats.p95);
        expect(stats.p95).toBeLessThanOrEqual(stats.p99);
    });

    it("accepts options without throwing", () => {
        expect(() =>
            benchmarkHttp2Request(5, {
                host: "example.com",
                port: 443,
                path: "/",
                profile: "chrome-140",
            }),
        ).not.toThrow();
    });
});
