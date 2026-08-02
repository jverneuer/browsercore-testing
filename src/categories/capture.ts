/**
 * Test Categories 14–15 — Packet Capture Comparison, Real World Compatibility.
 *
 * See docs/TEST-SUITE.md for the full acceptance criteria of each category.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID_CAPTURE = TestCategory.PacketCaptureComparison;
export const CATEGORY_ID_REALWORLD = TestCategory.RealWorldCompatibility;

describe(CATEGORY_ID_CAPTURE, () => {
    it.todo("generate reference capture per supported browser profile");
    it.todo("generate project capture per supported browser profile");
    it.todo("compare TLS records");
    it.todo("compare HTTP frames");
    it.todo("compare header order");
    it.todo("compare extension order");
    it.todo("compare packet sizes");
    it.todo("compare ALPN");
    it.todo("compare timing-independent message sequence");
    it.todo("ignore intentionally randomized fields (ephemeral keys, nonces, GREASE)");
});

describe(CATEGORY_ID_REALWORLD, () => {
    it.todo("interoperate with static websites");
    it.todo("interoperate with HTTP/2-only servers");
    it.todo("interoperate with CDNs");
    it.todo("interoperate with reverse proxies");
    it.todo("interoperate with TLS 1.2-only servers");
    it.todo("interoperate with TLS 1.3 servers");
    it.todo("interoperate with servers with large certificate chains");
});
