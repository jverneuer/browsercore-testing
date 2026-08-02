/**
 * Small shared helpers for @network/testing.
 */

import type {
    ComparisonResult,
    ComparisonResultWithIgnore,
    RandomizedField,
} from "./types.js";

/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 * Call in the `default` branch: `default: assertNever(x)`.
 * Adding a new union member forces every handler to compile-error until handled.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

/** Generate a unique TestCaseId (not cryptographically random). */
export function createId(prefix: "tc" = "tc"): string {
    return `${prefix}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** Format bytes as a lowercase hex string with no separators. */
export function bytesToHex(buf: Uint8Array): string {
    let out = "";
    for (let i = 0; i < buf.length; i++) {
        out += buf[i]!.toString(16).padStart(2, "0");
    }
    return out;
}

/**
 * Compare two byte arrays. Returns a {@link ComparisonResult} reporting whether
 * they match, the first divergence index (if any), and a message.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): ComparisonResult {
    if (a.length !== b.length) {
        return {
            matches: false,
            divergenceByteIndex: Math.min(a.length, b.length),
            message: `Length mismatch: ${a.length} vs ${b.length}`,
        };
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return {
                matches: false,
                divergenceByteIndex: i,
                message: `Byte ${i}: 0x${bytesToHex(a.subarray(i, i + 1))} vs 0x${bytesToHex(b.subarray(i, i + 1))}`,
            };
        }
    }
    return {
        matches: true,
        divergenceByteIndex: undefined,
        message: "equal",
    };
}

/**
 * Compare two byte arrays while masking byte ranges that are intentionally
 * randomized by the protocol spec (ephemeral keys, nonces, GREASE, random).
 *
 * Ranges in `ignore` are skipped when scanning for divergence. The returned
 * {@link ComparisonResultWithIgnore.maskedReports} lists the ranges that were
 * masked so callers can audit what was excluded.
 */
export function compareBytesWithIgnore(
    a: Uint8Array,
    b: Uint8Array,
    ignore: readonly RandomizedField[],
): ComparisonResultWithIgnore {
    // Defensive copy, sorted ascending so masking checks are O(log n) per byte.
    const ranges = [...ignore].sort((x, y) => x.byteOffset - y.byteOffset);

    const isMasked = (index: number): boolean => {
        for (const range of ranges) {
            if (index < range.byteOffset) return false;
            if (index < range.byteOffset + range.length) return true;
        }
        return false;
    };

    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
        const inA = i < a.length;
        const inB = i < b.length;
        if (!inA || !inB) {
            if (isMasked(i)) continue;
            return {
                matches: false,
                divergenceByteIndex: i,
                message: `Length divergence at byte ${i}: ${a.length} vs ${b.length}`,
                maskedRanges: ranges,
            };
        }
        if (a[i] !== b[i] && !isMasked(i)) {
            return {
                matches: false,
                divergenceByteIndex: i,
                message: `Byte ${i}: 0x${bytesToHex(a.subarray(i, i + 1))} vs 0x${bytesToHex(b.subarray(i, i + 1))}`,
                maskedRanges: ranges,
            };
        }
    }
    return {
        matches: true,
        divergenceByteIndex: undefined,
        message: "equal",
        maskedRanges: ranges,
    };
}
