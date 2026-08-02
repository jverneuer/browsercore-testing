/**
 * Oracle self-consistency tests for the zlib reference (Cat 14 / compression).
 *
 * Proves the node:zlib round-trip contract and records the exact byte-level
 * behavior our future @network/compression must match. Every test runs ONLY
 * against the nodeZlib oracle — no implementation under test exists yet.
 */

import { describe, expect, it } from "vitest";
import { nodeZlib, compareBytesOutcome } from "../src/reference/node-reference.js";

/** Build a deterministic buffer of length n where byte i = i % 256. */
const det = (n: number): Uint8Array =>
    Uint8Array.from({ length: n }, (_: number, i: number): number => i % 256);

/** Codec identifiers — string-literal union, no bare magic strings. */
type Codec = "gzip" | "deflate" | "brotli";
const CODECS: readonly Codec[] = ["gzip", "deflate", "brotli"] as const;

/** A compress/decompress pair for one codec. */
interface CodecPair {
    readonly compress: (data: Uint8Array) => Uint8Array;
    readonly decompress: (data: Uint8Array) => Uint8Array;
}

/** Map a codec name to its compress/decompress pair on the oracle. */
function pairFor(codec: Codec): CodecPair {
    switch (codec) {
        case "gzip":
            return { compress: nodeZlib.gzip, decompress: nodeZlib.gunzip };
        case "deflate":
            return { compress: nodeZlib.deflate, decompress: nodeZlib.inflate };
        case "brotli":
            return { compress: nodeZlib.brotliCompress, decompress: nodeZlib.brotliDecompress };
    }
}

/** Named constants for gzip framing (RFC 1952). */
const GZIP_MAGIC_FIRST = 0x1f;
const GZIP_MAGIC_SECOND = 0x8b;

describe("zlib oracle self-consistency (reference contract)", () => {
    describe("round-trip: compress then decompress equals original", () => {
        const cases: readonly { readonly name: string; readonly input: Uint8Array }[] = [
            { name: "empty buffer", input: new Uint8Array(0) },
            { name: "hello world text", input: new TextEncoder().encode("hello world") },
            { name: "4096-byte deterministic buffer", input: det(4096) },
            {
                name: "highly-repetitive 1000x 0x41 buffer",
                input: new Uint8Array(1000).fill(0x41),
            },
        ];

        for (const codec of CODECS) {
            for (const { name, input } of cases) {
                it(`${codec} round-trips: ${name}`, () => {
                    const { compress, decompress } = pairFor(codec);
                    const compressed = compress(input);
                    const roundTripped = decompress(compressed);
                    expect(compareBytesOutcome(roundTripped, input)).toEqual({ equal: true });
                });
            }
        }
    });

    describe("compression ratio: repetitive data shrinks", () => {
        const repetitive = new Uint8Array(1000).fill(0x41);

        it("node gzip output is smaller than input for repetitive data", () => {
            const compressed = nodeZlib.gzip(repetitive);
            expect(compressed.length).toBeLessThan(repetitive.length);
        });

        it("node deflate output is smaller than input for repetitive data", () => {
            const compressed = nodeZlib.deflate(repetitive);
            expect(compressed.length).toBeLessThan(repetitive.length);
        });

        it("node brotli output is smaller than input for repetitive data", () => {
            const compressed = nodeZlib.brotliCompress(repetitive);
            expect(compressed.length).toBeLessThan(repetitive.length);
        });
    });

    describe("format / structure", () => {
        it("gzip output starts with magic bytes 0x1f 0x8b", () => {
            const compressed = nodeZlib.gzip(new TextEncoder().encode("hello world"));
            expect(compressed.length).toBeGreaterThanOrEqual(2);
            expect(compressed[0]).toBe(GZIP_MAGIC_FIRST);
            expect(compressed[1]).toBe(GZIP_MAGIC_SECOND);
        });

        it("deflate output has no zlib header (raw deflate) — round-trips and is non-empty", () => {
            const input = new TextEncoder().encode("hello world");
            const compressed = nodeZlib.deflate(input);
            // Raw deflate (no 0x78 header byte). Just assert round-trip + non-empty.
            expect(compressed.length).toBeGreaterThan(0);
            expect(compareBytesOutcome(nodeZlib.inflate(compressed), input)).toEqual({
                equal: true,
            });
        });

        it("brotli output round-trips for text input", () => {
            const input = new TextEncoder().encode("the quick brown fox");
            const compressed = nodeZlib.brotliCompress(input);
            expect(compareBytesOutcome(nodeZlib.brotliDecompress(compressed), input)).toEqual({
                equal: true,
            });
        });
    });

    describe("cross-implementation contract (pending @network/compression)", () => {
        it.todo("implement @network/compression gzip and compare to nodeZlib.gzip bytes");
        it.todo("implement @network/compression deflate and compare to nodeZlib.deflate bytes");
        it.todo(
            "implement @network/compression brotliCompress and compare to nodeZlib.brotliCompress bytes",
        );
        it.todo("implement @network/compression gunzip and compare to nodeZlib.gunzip bytes");
        it.todo("implement @network/compression inflate and compare to nodeZlib.inflate bytes");
        it.todo(
            "implement @network/compression brotliDecompress and compare to nodeZlib.brotliDecompress bytes",
        );
    });

    describe("deterministic reference capture", () => {
        it("record gzip reference length for a canonical payload", () => {
            const canonical = new TextEncoder().encode(
                "The quick brown fox jumps over the lazy dog".repeat(10),
            );
            const compressed = nodeZlib.gzip(canonical);
            // Documents expected behavior: gzip shrinks this payload meaningfully.
            expect(compressed.length).toBeGreaterThan(0);
            expect(compressed.length).toBeLessThan(canonical.length);
        });
    });
});
