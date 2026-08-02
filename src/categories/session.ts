/**
 * Test Categories 11–12 — Session Resumption, Connection Reuse.
 *
 * See docs/TEST-SUITE.md for the full acceptance criteria of each category.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID_SESSION = TestCategory.SessionResumption;
export const CATEGORY_ID_REUSE = TestCategory.ConnectionReuse;

describe(CATEGORY_ID_SESSION, () => {
    it.todo("TLS session tickets");
    it.todo("session cache");
    it.todo("resumed handshake");
    it.todo("ticket expiration");
});

describe(CATEGORY_ID_REUSE, () => {
    it.todo("Keep-Alive");
    it.todo("HTTP/2 multiplexing");
    it.todo("connection pooling");
    it.todo("idle timeout");
    it.todo("maximum streams");
});
