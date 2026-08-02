/**
 * Test Category 1 — TCP Transport.
 *
 * Verify transport layer behaves correctly. See docs/TEST-SUITE.md
 * ("Test Category 1 — TCP Transport") for full acceptance criteria.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.TcpTransport;

describe(CATEGORY_ID, () => {
    it.todo("TCP connection establishment");
    it.todo("connection timeout handling");
    it.todo("read buffering");
    it.todo("partial packet handling");
    it.todo("large packet handling");
    it.todo("connection reuse");
    it.todo("graceful shutdown");
    it.todo("unexpected disconnect handling");
    it.todo("IPv4 support");
    it.todo("IPv6 support");
});
