/**
 * Test Category 8 — Cookie Behavior.
 *
 * Verify cookie parsing and policy. See docs/TEST-SUITE.md
 * ("Test Category 8 — Cookie Behavior") for full acceptance criteria.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.CookieBehavior;

describe(CATEGORY_ID, () => {
    it.todo("cookie parsing");
    it.todo("cookie expiration");
    it.todo("Secure cookies");
    it.todo("HttpOnly cookies");
    it.todo("SameSite cookies");
    it.todo("domain matching");
    it.todo("path matching");
    it.todo("cookie ordering");
});
