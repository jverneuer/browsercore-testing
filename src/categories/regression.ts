/**
 * Test Categories 16–17 — Regression Tests, Performance Benchmarks.
 *
 * See docs/TEST-SUITE.md for the full acceptance criteria of each category.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID_REGRESSION = TestCategory.Regression;
export const CATEGORY_ID_BENCHMARKS = TestCategory.PerformanceBenchmarks;

describe(CATEGORY_ID_REGRESSION, () => {
    it.todo("every discovered issue ships a permanent regression test");
    it.todo("regression test records serialized packets");
    it.todo("regression test records expected parser output");
    it.todo("regression test records expected state transitions");
    it.todo("regression test records expected network behavior");
    it.todo("previously fixed issues do not reappear unnoticed");
});

describe(CATEGORY_ID_BENCHMARKS, () => {
    it.todo("measure handshake latency");
    it.todo("measure requests per second");
    it.todo("measure memory usage");
    it.todo("measure CPU usage");
    it.todo("measure packet allocation");
    it.todo("measure TLS throughput");
    it.todo("measure HTTP/2 throughput");
    it.todo("benchmarks are tracked over time to identify regressions");
});
