/**
 * Bench module tests.
 *
 * benchmarkTlsHandshake / benchmarkHttp2Request are stubs that throw
 * "not implemented — see PLAN.md" until the underlying protocol stacks exist
 * (see src/bench/bench.ts). We assert they throw with the expected message so
 * the stub bodies stay covered; when implemented, these tests should be
 * replaced with real benchmark assertions.
 */

import { describe, expect, it } from "vitest";
import { benchmarkHttp2Request, benchmarkTlsHandshake } from "../src/index.js";

describe("benchmarkTlsHandshake (stub)", () => {
    it("throws 'not implemented'", () => {
        expect(() => benchmarkTlsHandshake(10)).toThrow("not implemented");
    });

    it("throws regardless of options", () => {
        expect(() =>
            benchmarkTlsHandshake(5, { host: "example.com", port: 443, profile: "chrome-140" }),
        ).toThrow("not implemented — see PLAN.md");
    });
});

describe("benchmarkHttp2Request (stub)", () => {
    it("throws 'not implemented'", () => {
        expect(() => benchmarkHttp2Request(10)).toThrow("not implemented");
    });

    it("throws regardless of options", () => {
        expect(() =>
            benchmarkHttp2Request(5, { host: "example.com", port: 443, path: "/", profile: "chrome-140" }),
        ).toThrow("not implemented — see PLAN.md");
    });
});
