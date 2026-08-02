/**
 * Test Category 9 — Compression.
 *
 * Verify gzip, brotli, deflate decoding behavior matches the Node.js reference
 * oracle (`nodeZlib`). The system under test is `@browsercore/compression`;
 * `nodeZlib` is the spec reference for these primitive layers. See
 * docs/TEST-SUITE.md ("Test Category 9 — Compression") for full acceptance
 * criteria.
 */

import { deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
    compression,
    UnsupportedEncodingError,
} from "@browsercore/compression";
import { nodeZlib } from "../reference/node-reference.js";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.Compression;

/** Deterministic payload: byte[i] = i % 256 (reproducible, never random). */
function detBuffer(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = i % 256;
    }
    return bytes;
}

describe(CATEGORY_ID, () => {
    const payload = detBuffer(1024);

    it("gzip decoding matches reference", () => {
        const compressed = nodeZlib.gzip(payload);
        const ours = compression.gunzip(compressed);
        const theirs = nodeZlib.gunzip(compressed);
        expect(ours).toEqual(theirs);
        expect(ours).toEqual(payload);
    });

    it("brotli decoding matches reference", () => {
        const compressed = nodeZlib.brotliCompress(payload);
        const ours = compression.brotliDecompress(compressed);
        const theirs = nodeZlib.brotliDecompress(compressed);
        expect(ours).toEqual(theirs);
        expect(ours).toEqual(payload);
    });

    it("deflate decoding matches reference (zlib-wrapped)", () => {
        const compressed = nodeZlib.deflate(payload);
        const ours = compression.inflate(compressed);
        const theirs = nodeZlib.inflate(compressed);
        expect(ours).toEqual(theirs);
        expect(ours).toEqual(payload);
    });

    it("deflate decoding falls back to raw inflate", () => {
        // A genuinely raw deflate stream (no zlib header) — inflateSync
        // rejects it, so decompress() must fall back to raw inflate. Built
        // with node:zlib's deflateRawSync, the only decoder that accepts it.
        const raw = new Uint8Array(deflateRawSync(payload));
        expect(compression.decompress(raw, "deflate")).toEqual(payload);
    });

    it("decompress() dispatches on the content-encoding token", () => {
        expect(compression.decompress(nodeZlib.gzip(payload), "gzip")).toEqual(payload);
        expect(compression.decompress(nodeZlib.deflate(payload), "deflate")).toEqual(payload);
        expect(compression.decompress(nodeZlib.brotliCompress(payload), "br")).toEqual(payload);
    });

    it("decompress() rejects an unsupported encoding", () => {
        expect(() => compression.decompress(payload, "zstd")).toThrow(UnsupportedEncodingError);
    });
});
