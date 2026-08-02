/**
 * RFC compliance test suite tests.
 *
 * runTlsCompliance / runHttp2Compliance / runHttp1Compliance are stubs that
 * throw "not implemented — see PLAN.md" until the underlying protocol stacks
 * exist (see src/rfc/rfcTests.ts). We assert they throw with the expected
 * message so the stub bodies stay covered; when implemented, replace these
 * with real compliance assertions.
 */

import { describe, expect, it } from "vitest";
import { runHttp1Compliance, runHttp2Compliance, runTlsCompliance } from "../src/index.js";

describe("runTlsCompliance (stub)", () => {
    it("throws 'not implemented'", () => {
        expect(() => runTlsCompliance()).toThrow("not implemented");
    });
});

describe("runHttp2Compliance (stub)", () => {
    it("throws 'not implemented'", () => {
        expect(() => runHttp2Compliance()).toThrow("not implemented");
    });
});

describe("runHttp1Compliance (stub)", () => {
    it("throws 'not implemented'", () => {
        expect(() => runHttp1Compliance()).toThrow("not implemented");
    });
});
