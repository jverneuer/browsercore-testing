/**
 * E2E — Phase 3: JA3 / JA4 golden hash verification (plan T7, T8).
 *
 * These tests fingerprint the *real* on-disk golden ClientHello captures and
 * assert the resulting JA3 digest and JA4 `t` part match the expected golden
 * hashes. The expected hashes below were recomputed independently from the
 * same `.bin` captures (verified against the tls.peet.ws oracle in
 * captures/DIVERGENCE_REPORT.md) and are pinned here so that any drift in the
 * fingerprint path — or silent replacement of a capture — fails the build.
 *
 * The chrome-140 / firefox-128 entries in the manifest are synthetic 96-byte
 * stubs (see DIVERGENCE_REPORT.md §TL;DR — they share JA3
 * `853b03398669dbeffb6116ecd6e6beb6`). They are NOT fingerprinted as profiles
 * here; a separate stub-guard block asserts they remain placeholders so that
 * replacing them with real wire data (the documented Phase 3 follow-up) fails
 * loudly and forces an explicit update.
 */

import { describe, expect, it } from "vitest";
import { loadGolden } from "../../src/golden/golden.js";
import { computeJa3, computeJa4 } from "../../src/fingerprint/index.js";
import type { CaptureId } from "../../src/types.js";

/** Expected JA3 + JA4 `t` part, recomputed from the real on-disk captures. */
interface GoldenFingerprint {
    readonly ja3: string;
    readonly ja4a: string;
}

/**
 * Real-wire golden captures. The chrome-131 / firefox-133 / safari-17
 * ClientHellos were captured via the transparent SOCKS5-relay method
 * (captures/_probe/) and are 517–1797 bytes with GREASE + randomized fields.
 */
const REAL_GOLDEN: Readonly<Record<string, GoldenFingerprint>> = {
    "chrome-131/tls/client_hello": {
        ja3: "ff0f40917e49fe7c78a7135fa409210a",
        ja4a: "t1516d12hh",
    },
    "firefox-133/tls/client_hello": {
        ja3: "2d692a4485ca2f5f2b10ecb2d2909ad3",
        ja4a: "t1716d12hh",
    },
    "safari-17/tls/client_hello": {
        ja3: "47032e00991c3937653c717e87ee499c",
        ja4a: "t2014d12hh",
    },
} as const;

/** The known JA3 of the synthetic 96-byte stubs (both stubs hash identical). */
const SYNTHETIC_STUB_JA3 = "853b03398669dbeffb6116ecd6e6beb6" as const;

/** Extract the JA4 `t` part (the `a` segment) from a full JA4 tag. */
function ja4TagToTag(ja4: string): string {
    const tag = ja4.split("_")[0];
    if (tag === undefined) {
        throw new Error(`JA4 tag has no "_"-separated segments: ${ja4}`);
    }
    return tag;
}

describe("T7 — JA3 matches golden (real captures)", () => {
    for (const [captureId, expected] of Object.entries(REAL_GOLDEN)) {
        it(`${captureId} JA3 == ${expected.ja3}`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);
            // Sanity: real captures are >500 bytes; stubs are 96.
            expect(capture.bytes.length).toBeGreaterThan(500);

            const ja3 = computeJa3(capture.bytes);
            expect(ja3).toMatch(/^[0-9a-f]{32}$/);
            expect(ja3).toBe(expected.ja3);
        });
    }
});

describe("T8 — JA4 t part matches golden (real captures)", () => {
    for (const [captureId, expected] of Object.entries(REAL_GOLDEN)) {
        it(`${captureId} JA4_a == ${expected.ja4a}`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);

            const ja4 = computeJa4(capture.bytes);
            // Structural: four "_" -separated segments.
            expect(ja4.split("_")).toHaveLength(4);

            const tag = ja4TagToTag(ja4);
            expect(tag).toBe(expected.ja4a);
        });
    }
});

describe("Synthetic stub guard — chrome-140 / firefox-128 are placeholders", () => {
    // Both stubs are identical 96-byte placeholders that share one JA3. If a
    // future commit replaces either with real wire data, this assertion fails
    // and forces an explicit update to REAL_GOLDEN above. This is the build's
    // defence against the stubs silently becoming "verified" golden captures.
    const stubIds = [
        "chrome-140/tls/client_hello",
        "firefox-128/tls/client_hello",
    ] as const;

    for (const captureId of stubIds) {
        it(`${captureId} is still the known synthetic stub (JA3 ${SYNTHETIC_STUB_JA3})`, () => {
            const capture = loadGolden(captureId as CaptureId);
            expect(capture.bytes.length).toBe(96); // stub size, not a real hello
            const ja3 = computeJa3(capture.bytes);
            expect(ja3).toBe(SYNTHETIC_STUB_JA3);
        });
    }
});
