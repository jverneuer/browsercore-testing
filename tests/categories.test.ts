/**
 * Top-level suite that pulls in all 17 test categories. Real assertions live
 * alongside trivially-testable logic in each category file; everything else
 * is an `it.todo` placeholder listing the acceptance criteria from
 * docs/TEST-SUITE.md.
 */

import { describe, expect, it } from "vitest";
import { TestCategory, type TestCategoryId } from "../src/index.js";

// Import every category so its `describe`/`it` blocks register with vitest.
import "./../src/categories/transport.js";
import "./../src/categories/tls.js";
import "./../src/categories/http.js";
import "./../src/categories/cookies.js";
import "./../src/categories/compression.js";
import "./../src/categories/redirects.js";
import "./../src/categories/session.js";
import "./../src/categories/errors.js";
import "./../src/categories/capture.js";
import "./../src/categories/regression.js";

describe("TestCategory model", () => {
    it("defines all 17 category ids", () => {
        const ids: readonly TestCategoryId[] = [
            TestCategory.TcpTransport,
            TestCategory.TlsSerialization,
            TestCategory.BrowserProfileComparison,
            TestCategory.TlsFingerprint,
            TestCategory.Http1,
            TestCategory.Http2,
            TestCategory.HeaderProfiles,
            TestCategory.CookieBehavior,
            TestCategory.Compression,
            TestCategory.RedirectHandling,
            TestCategory.SessionResumption,
            TestCategory.ConnectionReuse,
            TestCategory.ErrorHandling,
            TestCategory.PacketCaptureComparison,
            TestCategory.RealWorldCompatibility,
            TestCategory.Regression,
            TestCategory.PerformanceBenchmarks,
        ];
        expect(ids).toHaveLength(17);
    });

    it("uses stable kebab-case ids (no magic strings)", () => {
        expect(TestCategory.TcpTransport).toBe("tcp-transport");
        expect(TestCategory.PerformanceBenchmarks).toBe("performance-benchmarks");
    });
});
