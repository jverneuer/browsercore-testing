/**
 * E2E — Phase 2/3: sink-captured bytes correlate to golden captures (masked).
 *
 * Proves the byte-masking comparison path that a live sink server would rely
 * on (`compareBytesWithIgnore` + the `randomizedFields` sidecar). Each real
 * golden capture stands in for "what the sink would have captured": the
 * capture bytes, compared against themselves with the profile's randomized
 * ranges masked, MUST match; a byte-flip OUTSIDE the masked ranges MUST be
 * detected; a byte-flip INSIDE a masked range MUST be tolerated. This locks
 * in the contract that randomized fields (client_random, GREASE extension
 * block) are excluded from the equality check while constant signal is not.
 *
 * Per the E2E plan §3.2, the tests read `randomizedFields` from the
 * `.meta.json` sidecars rather than hardcoding offsets — the offset of the
 * randomized region is a function of the parsed structure, not a constant.
 *
 * chrome-140 / firefox-128 are synthetic 96-byte stubs (see
 * DIVERGENCE_REPORT.md) whose `.meta.json` declares synthetic offsets; they
 * are intentionally excluded here and covered by the stub-guard in
 * ja3-ja4.test.ts. Only the real-wire captures (517–1797 bytes) are exercised.
 */

import { describe, expect, it } from "vitest";
import { loadGolden, loadCaptureMeta } from "../../src/golden/golden.js";
import { compareBytesWithIgnore } from "../../src/utils.js";
import type { CaptureId } from "../../src/types.js";

/** Real-wire golden captures only — the stubs are synthetic placeholders. */
const REAL_TLS_CAPTURES: readonly string[] = [
    "chrome-131/tls/client_hello",
    "firefox-133/tls/client_hello",
    "safari-17/tls/client_hello",
] as const;

describe("Golden correlates — self-match under randomized-field mask", () => {
    for (const captureId of REAL_TLS_CAPTURES) {
        it(`${captureId} matches itself when randomized fields are masked`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);
            const meta = loadCaptureMeta(id);

            // Real wire ClientHellos are >500 bytes; the stubs are 96.
            expect(capture.bytes.length).toBeGreaterThan(500);
            // Every real capture declares at least the client_random range.
            expect(meta.randomizedFields.length).toBeGreaterThanOrEqual(1);

            const result = compareBytesWithIgnore(
                capture.bytes,
                capture.bytes,
                meta.randomizedFields,
            );
            expect(result.matches).toBe(true);
            expect(result.divergenceByteIndex).toBeUndefined();
            expect(result.maskedRanges).toEqual(meta.randomizedFields);
        });
    }
});

describe("Golden correlates — divergence OUTSIDE the mask is detected", () => {
    // Byte 0 is the TLS record content type (0x16 = Handshake). It is constant
    // across all captures and not in any masked range, so flipping it proves
    // the comparator still detects real differences.
    const CONSTANT_UNMASKED_BYTE = 0;

    for (const captureId of REAL_TLS_CAPTURES) {
        it(`${captureId} detects a flip at byte ${CONSTANT_UNMASKED_BYTE}`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);
            const meta = loadCaptureMeta(id);

            // Pre-condition: the byte we flip is genuinely outside the mask.
            const masked = meta.randomizedFields.some(
                (f) =>
                    CONSTANT_UNMASKED_BYTE >= f.byteOffset &&
                    CONSTANT_UNMASKED_BYTE < f.byteOffset + f.length,
            );
            expect(masked).toBe(false);

            const mutated = new Uint8Array(capture.bytes);
            mutated[CONSTANT_UNMASKED_BYTE] = mutated[CONSTANT_UNMASKED_BYTE]! ^ 0xff;

            const result = compareBytesWithIgnore(
                capture.bytes,
                mutated,
                meta.randomizedFields,
            );
            expect(result.matches).toBe(false);
            expect(result.divergenceByteIndex).toBe(CONSTANT_UNMASKED_BYTE);
        });
    }
});

describe("Golden correlates — divergence INSIDE the mask is tolerated", () => {
    // client_random starts at byte offset 12 (record header 5 bytes +
    // handshake type 1 + length 3 + client_version 2 = 11, then byte 12 is
    // the first random byte) and is masked with reason "random" in all three
    // captures. The masks read from the sidecar confirm this; we pick a byte
    // comfortably inside that range and prove the flip is tolerated.
    const RANDOM_BYTE_OFFSET = 20;

    for (const captureId of REAL_TLS_CAPTURES) {
        it(`${captureId} tolerates a flip inside the client_random mask`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);
            const meta = loadCaptureMeta(id);

            // Pre-condition: byte 20 is within the "random" masked range.
            const randomRange = meta.randomizedFields.find(
                (f) => f.reason === "random",
            );
            expect(randomRange).toBeDefined();
            expect(RANDOM_BYTE_OFFSET).toBeGreaterThanOrEqual(randomRange!.byteOffset);
            expect(RANDOM_BYTE_OFFSET).toBeLessThan(
                randomRange!.byteOffset + randomRange!.length,
            );

            const mutated = new Uint8Array(capture.bytes);
            mutated[RANDOM_BYTE_OFFSET] = mutated[RANDOM_BYTE_OFFSET]! ^ 0xff;

            const result = compareBytesWithIgnore(
                capture.bytes,
                mutated,
                meta.randomizedFields,
            );
            expect(result.matches).toBe(true);
            expect(result.divergenceByteIndex).toBeUndefined();
        });
    }
});

describe("Golden correlates — length divergence outside the mask is detected", () => {
    // These real captures mask the GREASE extension block from its start all
    // the way to the end of the byte array, so removing bytes from the tail
    // only removes masked bytes (correctly tolerated). To exercise the
    // unmasked length-divergence path we instead drop bytes from the FRONT:
    // the TLS record header (bytes 0–4), handshake type/length (5–7), and
    // client_version (8–9) are all outside every capture's mask, so a
    // front-truncated neighbour diverges on byte 0 (content type 0x16) before
    // the comparator ever reaches the length tail.
    const FRONT_SKIP = 10;

    for (const captureId of REAL_TLS_CAPTURES) {
        it(`${captureId} detects a front-truncated neighbour as divergence`, () => {
            const id = captureId as CaptureId;
            const capture = loadGolden(id);
            const meta = loadCaptureMeta(id);

            // Pre-condition: the bytes we drop from the front include at least
            // one unmasked byte (byte 0, the 0x16 record content type).
            const frontMasked = meta.randomizedFields.some(
                (f) =>
                    0 >= f.byteOffset && 0 < f.byteOffset + f.length,
            );
            expect(frontMasked).toBe(false);

            const truncated = capture.bytes.subarray(FRONT_SKIP);
            expect(truncated.length).toBeLessThan(capture.bytes.length);

            const result = compareBytesWithIgnore(
                capture.bytes,
                truncated,
                meta.randomizedFields,
            );
            expect(result.matches).toBe(false);
            // Divergence is reported at the first unmasked byte (0x16 at 0).
            expect(result.divergenceByteIndex).toBe(0);
        });
    }
});
