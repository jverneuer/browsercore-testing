/**
 * Test Categories 2–4 — TLS Serialization, Browser Profile Comparison,
 * TLS Fingerprint.
 *
 * See docs/TEST-SUITE.md for the full acceptance criteria of each category.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID_TLS = TestCategory.TlsSerialization;
export const CATEGORY_ID_PROFILE = TestCategory.BrowserProfileComparison;
export const CATEGORY_ID_FINGERPRINT = TestCategory.TlsFingerprint;

describe(CATEGORY_ID_TLS, () => {
    it.todo("ClientHello serialization");
    it.todo("ServerHello parsing");
    it.todo("extension parsing");
    it.todo("record fragmentation");
    it.todo("Finished message generation");
    it.todo("alert handling");
    it.todo("key schedule generation");
    it.todo("session resumption");
});

describe(CATEGORY_ID_PROFILE, () => {
    it.todo("ClientHello: TLS version matches profile");
    it.todo("ClientHello: cipher suite list + ordering matches profile");
    it.todo("ClientHello: extension ordering matches profile");
    it.todo("ClientHello: supported groups match profile");
    it.todo("ClientHello: key shares match profile");
    it.todo("ClientHello: signature algorithms match profile");
    it.todo("ClientHello: ALPN list matches profile");
    it.todo("ClientHello: GREASE values match profile");
    it.todo("ClientHello: session ID length matches profile");
    it.todo("ClientHello: compression methods match profile");
    it.todo("ClientHello: PSK extension matches profile");
    it.todo("ClientHello: padding extension matches profile");
    it.todo("ClientHello: SNI extension matches profile");
    it.todo("ClientHello: record version matches profile");
    it.todo("ClientHello: record fragmentation matches profile");
});

describe(CATEGORY_ID_FINGERPRINT, () => {
    it.todo("JA3 fingerprint matches configured profile");
    it.todo("JA4 fingerprint matches configured profile (where applicable)");
    it.todo("ALPN negotiation matches configured profile");
    it.todo("negotiated cipher suite matches configured profile");
    it.todo("negotiated protocol version matches configured profile");
    it.todo("supported signature algorithms match configured profile");
    it.todo("supported elliptic curves match configured profile");
});
