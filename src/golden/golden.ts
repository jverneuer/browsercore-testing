/**
 * Golden packet capture loading + comparison.
 *
 * Captures live on disk as a `.bin` (raw wire bytes) plus a `.meta.json`
 * sidecar describing the capture and listing the byte ranges that are
 * intentionally randomized by the protocol spec (ephemeral keys, nonces,
 * GREASE, client_random). Those ranges MUST be masked before comparison —
 * that is the core mechanism behind Category 14 (packet capture comparison).
 *
 * CaptureId format: a path-like triple `${profile}/${protocol}/${record}`
 * (e.g. `chrome-140/tls/client_hello`) that maps directly onto the
 * `captures/<profile>/<protocol>/<record>.{bin,meta.json}` layout.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type {
    CaptureId,
    CaptureMeta,
    ComparisonResult,
    ComparisonResultWithIgnore,
    GoldenCapture,
    RandomizedField,
} from "../types.js";
import { compareBytes, compareBytesWithIgnore } from "../utils.js";
import { GoldenMismatchError, TestingError } from "../errors.js";

const here = import.meta.dirname;
// src/golden -> package root -> captures/
const capturesDir = join(here, "..", "..", "captures");

/** Parse a CaptureId of the form `${profile}/${protocol}/${record}`. */
function parseCaptureId(captureId: CaptureId): {
    readonly profile: string;
    readonly protocol: string;
    readonly record: string;
} {
    const EXPECTED_FORMAT = `\${profile}/\${protocol}/\${record}`;
    const parts = captureId.split("/");
    if (parts.length !== 3) {
        throw new TestingError(
            `Malformed CaptureId "${captureId}" — expected ${EXPECTED_FORMAT}`,
        );
    }
    const [profile, protocol, record] = parts;
    if (profile === undefined || protocol === undefined || record === undefined) {
        throw new TestingError(
            `Malformed CaptureId "${captureId}" — expected ${EXPECTED_FORMAT}`,
        );
    }
    return { profile, protocol, record };
}

/**
 * Validate unknown JSON data as a {@link CaptureMeta} (no zod dep here).
 *
 * Exported for unit testing the validation branches — the error paths are only
 * reachable with a malformed sidecar, which the on-disk captures are not.
 */
export function parseCaptureMeta(raw: unknown, captureId: string): CaptureMeta {
    if (typeof raw !== "object" || raw === null) {
        throw new TestingError(`Capture meta for ${captureId} is not an object`);
    }
    const obj = raw as Record<string, unknown>;

    const source = obj.source;
    if (source !== "curl-impersonate" && source !== "real-browser") {
        throw new TestingError(
            `Capture meta for ${captureId} has invalid source: ${String(source)}`,
        );
    }
    const protocol = obj.protocol;
    if (protocol !== "tls" && protocol !== "http2" && protocol !== "http1" && protocol !== "tcp") {
        throw new TestingError(
            `Capture meta for ${captureId} has invalid protocol: ${String(protocol)}`,
        );
    }
    const record = obj.record;
    if (
        record !== "client_hello" &&
        record !== "settings" &&
        record !== "headers" &&
        record !== "server_hello"
    ) {
        throw new TestingError(
            `Capture meta for ${captureId} has invalid record: ${String(record)}`,
        );
    }
    const description = obj.description;
    if (typeof description !== "string") {
        throw new TestingError(`Capture meta for ${captureId} has non-string description`);
    }
    const createdAt = obj.createdAt;
    if (typeof createdAt !== "string") {
        throw new TestingError(`Capture meta for ${captureId} has non-string createdAt`);
    }
    const randomizedFields = parseRandomizedFields(obj.randomizedFields, captureId);

    return {
        source,
        profile: obj.profile as CaptureMeta["profile"],
        protocol,
        record,
        description,
        randomizedFields,
        createdAt,
    };
}

/**
 * Validate unknown data as a list of {@link RandomizedField}.
 *
 * Exported for unit testing the validation branches — the error paths are only
 * reachable with a malformed sidecar, which the on-disk captures are not.
 */
export function parseRandomizedFields(raw: unknown, captureId: string): readonly RandomizedField[] {
    if (!Array.isArray(raw)) {
        throw new TestingError(`Capture meta for ${captureId} has non-array randomizedFields`);
    }
    return raw.map((item, i) => {
        if (typeof item !== "object" || item === null) {
            throw new TestingError(
                `Capture meta for ${captureId} randomizedFields[${i}] is not an object`,
            );
        }
        const obj = item as Record<string, unknown>;
        const byteOffset = obj.byteOffset;
        if (typeof byteOffset !== "number" || byteOffset < 0) {
            throw new TestingError(
                `Capture meta for ${captureId} randomizedFields[${i}].byteOffset invalid`,
            );
        }
        const length = obj.length;
        if (typeof length !== "number" || length < 0) {
            throw new TestingError(
                `Capture meta for ${captureId} randomizedFields[${i}].length invalid`,
            );
        }
        const reason = obj.reason;
        if (reason !== "ephemeral_key" && reason !== "nonce" && reason !== "grease" && reason !== "random") {
            throw new TestingError(
                `Capture meta for ${captureId} randomizedFields[${i}].reason invalid: ${String(reason)}`,
            );
        }
        return { byteOffset, length, reason };
    });
}

/** Resolve a CaptureId to its on-disk `.bin` + `.meta.json` paths. */
function resolveCapturePaths(captureId: CaptureId): {
    readonly binPath: string;
    readonly metaPath: string;
} {
    const { profile, protocol, record } = parseCaptureId(captureId);
    const base = join(capturesDir, profile, protocol, record);
    return { binPath: `${base}.bin`, metaPath: `${base}.meta.json` };
}

/**
 * Load a golden capture by id.
 *
 * Reads `<captureId>.bin` and its sibling `.meta.json` from the captures
 * directory, validates the sidecar, and returns a typed {@link GoldenCapture}.
 * Throws {@link TestingError} when the id is malformed, the files are
 * missing, or the sidecar fails validation.
 */
export function loadGolden(captureId: CaptureId): GoldenCapture {
    const { binPath, metaPath } = resolveCapturePaths(captureId);

    let bytes: Uint8Array;
    try {
        bytes = readFileSync(binPath);
    } catch (e) {
        const cause = e instanceof Error ? e : new Error(String(e));
        throw new TestingError(`Failed to read capture bytes at ${binPath}`, { cause });
    }

    let meta: unknown;
    try {
        meta = JSON.parse(readFileSync(metaPath, "utf8")) as unknown;
    } catch (e) {
        const cause = e instanceof Error ? e : new Error(String(e));
        throw new TestingError(`Failed to read/parse capture meta at ${metaPath}`, { cause });
    }

    const parsed = parseCaptureMeta(meta, captureId);
    return {
        id: captureId,
        source: parsed.source === "curl-impersonate" ? parseSource(parsed.profile) : "chrome-140",
        protocol: parsed.protocol,
        bytes,
        description: parsed.description,
    };
}

/** Derive a {@link CaptureSource} from a profile id (best-effort). */
function parseSource(profile: CaptureMeta["profile"]): GoldenCapture["source"] {
    const p = String(profile);
    if (p.startsWith("chrome")) {
        return "chrome-140";
    }
    if (p.startsWith("firefox")) {
        return "firefox-135";
    }
    if (p.startsWith("safari")) {
        return "safari-18";
    }
    if (p.startsWith("edge")) {
        return "edge-140";
    }
    return "chrome-140";
}

/** Load the {@link CaptureMeta} sidecar for a capture. */
export function loadCaptureMeta(captureId: CaptureId): CaptureMeta {
    const { metaPath } = resolveCapturePaths(captureId);
    let raw: unknown;
    try {
        raw = JSON.parse(readFileSync(metaPath, "utf8")) as unknown;
    } catch (e) {
        const cause = e instanceof Error ? e : new Error(String(e));
        throw new TestingError(`Failed to read/parse capture meta at ${metaPath}`, { cause });
    }
    return parseCaptureMeta(raw, captureId);
}

/**
 * Compare actual bytes against a golden capture. Real byte comparison —
 * throws {@link GoldenMismatchError} when they diverge.
 *
 * Uses a strict byte comparison (no randomized-field masking). For the
 * tolerant comparison used by Category 14, see
 * {@link compareAgainstGoldenWithIgnore}.
 */
export function compareAgainstGolden(actual: Uint8Array, captureId: CaptureId): ComparisonResult {
    let expected: Uint8Array;
    try {
        expected = loadGolden(captureId).bytes;
    } catch (e) {
        const cause = e instanceof Error ? e : new Error(String(e));
        throw new TestingError(`Failed to load golden ${captureId}`, { cause });
    }
    const result = compareBytes(actual, expected);
    if (!result.matches) {
        throw new GoldenMismatchError(captureId, result.divergenceByteIndex ?? actual.length);
    }
    return result;
}

/**
 * Compare actual bytes against a golden capture while masking the byte ranges
 * the protocol intentionally randomizes (ephemeral keys, nonces, GREASE,
 * client_random). This is the Category 14 tolerant comparison.
 *
 * Returns a {@link ComparisonResultWithIgnore} that reports which ranges were
 * masked. Throws {@link GoldenMismatchError} only when bytes OUTSIDE the
 * masked ranges diverge.
 */
export function compareAgainstGoldenWithIgnore(
    actual: Uint8Array,
    captureId: CaptureId,
): ComparisonResultWithIgnore {
    let expected: Uint8Array;
    let meta: CaptureMeta;
    try {
        expected = loadGolden(captureId).bytes;
        meta = loadCaptureMeta(captureId);
    } catch (e) {
        const cause = e instanceof Error ? e : new Error(String(e));
        throw new TestingError(`Failed to load golden ${captureId}`, { cause });
    }
    const result = compareBytesWithIgnore(actual, expected, meta.randomizedFields);
    if (!result.matches) {
        throw new GoldenMismatchError(captureId, result.divergenceByteIndex ?? actual.length);
    }
    return result;
}
