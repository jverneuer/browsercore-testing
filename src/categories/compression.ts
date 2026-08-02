/**
 * Test Category 9 — Compression.
 *
 * Verify gzip, brotli, deflate decoding behavior. See docs/TEST-SUITE.md
 * ("Test Category 9 — Compression") for full acceptance criteria.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.Compression;

describe(CATEGORY_ID, () => {
    it.todo("gzip decoding matches reference");
    it.todo("brotli decoding matches reference");
    it.todo("deflate decoding matches reference");
});
