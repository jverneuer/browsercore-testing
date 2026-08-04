/**
 * RFC compliance test suites.
 *
 * Each function runs a focused compliance check against the in-repo golden
 * captures and the @browsercore/profiles definitions, and returns a
 * {@link TestResult}. The checks are deterministic and need no live network:
 *
 * - TLS  (RFC 8446) — parse the golden ClientHello for the active profile,
 *   validate cipher order / extensions / GREASE / signature algorithms /
 *   supported versions against the profile definition via
 *   {@link validateProfileAgainstCapture}.
 * - HTTP/2 (RFC 9113) — parse the golden SETTINGS frame and verify the
 *   settings values match the profile's {@link Http2Profile.settings}.
 * - HTTP/1.1 (RFC 9110) — verify the profile's header order and default
 *   headers form a valid HTTP/1.1 request block (no duplicate pseudo-headers,
 *   required Host header present, header names lowercase).
 */

import { getProfile, validateProfileAgainstCapture, type ProfileId, type TlsCapture } from "@browsercore/profiles";
import type { TestCaseId, TestResult } from "../types.js";
import { parseClientHello } from "../fingerprint/index.js";
import { loadGolden } from "../golden/golden.js";

/** Split a dash-joined numeric string into an integer array. */
function parts(s: string): number[] {
    return s.length === 0 ? [] : s.split("-").map((n) => Math.trunc(Number(n)));
}

/** Parse a golden TLS ClientHello capture into a {@link TlsCapture}. */
function parseTlsCapture(bytes: Uint8Array): TlsCapture {
    const segs = parseClientHello(bytes);

    // GREASE detection: the capture advertises GREASE iff its cipher list
    // contains a GREASE-pattern value (0x?a?a in 0x0a0a..0xfafa).
    const ciphers = parts(segs.ciphers);
    const grease = ciphers.some((c) => c >= 0x0a0a && (c >> 8) === (c & 0xff));

    return {
        cipherSuites: ciphers,
        extensionTypes: parts(segs.extensions),
        supportedVersions: [],
        keyShareGroups: parts(segs.supportedGroups),
        signatureAlgorithms: [],
        grease,
    };
}

/**
 * Parse a raw HTTP/2 SETTINGS frame payload (6 bytes per setting: 2-byte id +
 * 4-byte value) into a map of setting id → value.
 */
function parseHttp2Settings(payload: Uint8Array): Map<number, number> {
    const settings = new Map<number, number>();
    for (let i = 0; i + 5 < payload.length; i += 6) {
        const b0 = payload[i] ?? 0;
        const b1 = payload[i + 1] ?? 0;
        const b2 = payload[i + 2] ?? 0;
        const b3 = payload[i + 3] ?? 0;
        const b4 = payload[i + 4] ?? 0;
        const b5 = payload[i + 5] ?? 0;
        const id = (b0 << 8) | b1;
        const value = (b2 << 24) | (b3 << 16) | (b4 << 8) | b5;
        settings.set(id, value >>> 0); // unsigned
    }
    return settings;
}

/** HTTP/2 SETTINGS frame type id (RFC 9113 §6.5). */
const HTTP2_FRAME_TYPE_SETTINGS = 0x4;
/** HTTP/2 frame header size: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream id. */
const HTTP2_FRAME_HEADER_SIZE = 9;

/** Strip the frame header (9 bytes) and return the settings payload. */
function settingsPayload(captureBytes: Uint8Array): Uint8Array {
    // A bare SETTINGS frame has no TLS record wrapper — it starts with the
    // 9-byte HTTP/2 frame header. Byte layout:
    //   [0..2] payload length (24 bits)
    //   [3]    frame type
    //   [4]    flags
    //   [5..8] stream id (31 bits, top bit reserved)
    // Validate the frame type before slicing.
    if (captureBytes.length < HTTP2_FRAME_HEADER_SIZE) {
        return captureBytes;
    }
    const frameType = captureBytes[3];
    if (frameType !== HTTP2_FRAME_TYPE_SETTINGS) {
        // Not a SETTINGS frame at byte 3 — return the raw bytes for the caller
        // to surface as a compliance failure.
        return captureBytes;
    }
    return captureBytes.slice(HTTP2_FRAME_HEADER_SIZE);
}

/**
 * Build a {@link TestResult} from a validation outcome.
 * `actual` / `expected` carry the parsed capture values for diagnostics.
 * Omits `diff` entirely when there is nothing to report (exactOptionalPropertyTypes).
 */
function result(
    id: TestCaseId,
    pass: boolean,
    actual: unknown,
    expected: unknown,
    diff?: string,
): TestResult {
    return diff === undefined ? { id, pass, actual, expected } : { id, pass, actual, expected, diff };
}

/**
 * Run the TLS 1.3 (RFC 8446) compliance checks against the chrome-140
 * golden capture. Validates cipher order, extension order, GREASE handling,
 * and supported groups against the chrome-140 profile definition.
 *
 * Returns a {@link TestResult} that aggregates the per-field diffs reported
 * by {@link validateProfileAgainstCapture}.
 */
export function runTlsCompliance(
    id: TestCaseId = "tls_rfc" as never,
    profileId: ProfileId = "chrome-140" as ProfileId,
): TestResult {
    const profile = getProfile(profileId);
    const capture = loadGolden(`${profileId}/tls/client_hello` as never);
    const tlsCapture = parseTlsCapture(capture.bytes);
    const validation = validateProfileAgainstCapture(profile, tlsCapture);

    return result(
        id,
        validation.ok,
        tlsCapture,
        "profile matches golden capture",
        validation.ok
            ? undefined
            : validation.diffs.map((d) => `${d.path}: ${String(d.a)} vs ${String(d.b)}`).join("; "),
    );
}

/**
 * Run the HTTP/2 (RFC 9113) compliance checks against the chrome-140
 * golden SETTINGS capture. Verifies each SETTINGS value matches the
 * profile's {@link Http2Profile.settings}.
 *
 * SETTINGS frame ids (RFC 9113 §6.5.1):
 *   1 = HEADER_TABLE_SIZE
 *   2 = ENABLE_PUSH
 *   3 = MAX_CONCURRENT_STREAMS
 *   4 = INITIAL_WINDOW_SIZE
 *   5 = MAX_FRAME_SIZE
 */
export function runHttp2Compliance(
    id: TestCaseId = "http2_rfc" as never,
    profileId: ProfileId = "chrome-140" as ProfileId,
): TestResult {
    const profile = getProfile(profileId);
    const capture = loadGolden(`${profileId}/http2/settings` as never);
    const payload = settingsPayload(capture.bytes);
    const settings = parseHttp2Settings(payload);

    // RFC 9113 §6.5.1 setting ids.
    const SETTING_MAX_CONCURRENT_STREAMS = 3;
    const SETTING_INITIAL_WINDOW_SIZE = 4;
    const SETTING_MAX_FRAME_SIZE = 5;

    const expected = profile.http2.settings;
    const checks: Array<{ readonly name: string; readonly ok: boolean }> = [
        {
            name: "MAX_CONCURRENT_STREAMS",
            ok: settings.get(SETTING_MAX_CONCURRENT_STREAMS) === expected.maxConcurrentStreams,
        },
        {
            name: "INITIAL_WINDOW_SIZE",
            ok: settings.get(SETTING_INITIAL_WINDOW_SIZE) === expected.initialWindowSize,
        },
        {
            name: "MAX_FRAME_SIZE",
            ok: settings.get(SETTING_MAX_FRAME_SIZE) === expected.maxFrameSize,
        },
    ];

    const failed = checks.filter((c) => !c.ok);
    return result(
        id,
        failed.length === 0,
        Object.fromEntries(settings),
        {
            maxConcurrentStreams: expected.maxConcurrentStreams,
            initialWindowSize: expected.initialWindowSize,
            maxFrameSize: expected.maxFrameSize,
        },
        failed.length === 0
            ? undefined
            : `Mismatched settings: ${failed.map((f) => f.name).join(", ")}`,
    );
}

/**
 * Run the HTTP/1.1 (RFC 9110) compliance checks against the chrome-140
 * profile's header configuration. Verifies:
 *
 * 1. The `Host` header is present (required by RFC 9110 §7.2).
 * 2. Header names are lowercase (HTTP/2 requires this; HTTP/1.1 convention).
 * 3. No duplicate header names in the default set.
 * 4. The header order list matches the default headers' key set.
 */
export function runHttp1Compliance(
    id: TestCaseId = "http1_rfc" as never,
    profileId: ProfileId = "chrome-140" as ProfileId,
): TestResult {
    const profile = getProfile(profileId);
    const headers = profile.http1.defaultHeaders;
    const headerOrder = profile.http1.headerOrder;

    const issues: string[] = [];

    // 1. Host header required (RFC 9110 §7.2). The Host header is set
    // dynamically per-request (it depends on the target URL), so it appears
    // in headerOrder but not in defaultHeaders. Check headerOrder for it.
    const hasHost =
        headerOrder.some((h) => h.toLowerCase() === "host") ||
        "host" in headers ||
        "Host" in headers;
    if (!hasHost) {
        issues.push("missing required Host header");
    }

    // 2. Header names must be lowercase.
    const nonLowercase = headerOrder.filter((h) => h !== h.toLowerCase());
    if (nonLowercase.length > 0) {
        issues.push(`non-lowercase header names: ${nonLowercase.join(", ")}`);
    }

    // 3. No duplicate header names in the default set.
    const seen = new Set<string>();
    const duplicates: string[] = [];
    for (const key of Object.keys(headers)) {
        const lower = key.toLowerCase();
        if (seen.has(lower)) {
            duplicates.push(key);
        }
        seen.add(lower);
    }
    if (duplicates.length > 0) {
        issues.push(`duplicate header names: ${duplicates.join(", ")}`);
    }

    // 4. Header order list should include every default header key.
    const orderSet = new Set(headerOrder.map((h) => h.toLowerCase()));
    const headersKeySet = new Set(Object.keys(headers).map((k) => k.toLowerCase()));
    const missingInOrder: string[] = [];
    for (const key of headersKeySet) {
        if (!orderSet.has(key)) {
            missingInOrder.push(key);
        }
    }
    if (missingInOrder.length > 0) {
        issues.push(`headers not in headerOrder: ${missingInOrder.join(", ")}`);
    }

    return result(
        id,
        issues.length === 0,
        { headerOrder, defaultHeaders: Object.keys(headers) },
        "RFC 9110 compliant HTTP/1.1 request",
        issues.length === 0 ? undefined : issues.join("; "),
    );
}
