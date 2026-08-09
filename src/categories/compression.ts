/**
 * Test Category 9 — Compression.
 *
 * Verify gzip, brotli, deflate decoding behavior matches the Node.js reference
 * oracle (`nodeZlib`). The system under test is a `CompressionProvider`
 * implementation backed by node:zlib; `nodeZlib` is the spec reference for
 * these primitive layers. The runtime implementation lives in browsersmith
 * (Layer 5), so this repo exercises the `CompressionProvider` contract with a
 * local Node-backed double. See docs/TEST-SUITE.md ("Test Category 9 —
 * Compression") for full acceptance criteria.
 */

import {
    brotliCompressSync,
    brotliDecompressSync,
    deflateRawSync,
    deflateSync,
    gunzipSync,
    gzipSync,
    inflateRawSync,
    inflateSync,
} from "node:zlib";
import { describe, expect, it } from "vitest";
import type { CompressionProvider, ContentEncoding } from "@browsercore/compression";
import { UnsupportedEncodingError } from "@browsercore/compression";
import { nodeZlib } from "../reference/node-reference.js";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.Compression;

/**
 * Local Node-backed `CompressionProvider` double. The production implementation
 * lives in browsersmith; this repo exercises the contract against the Node
 * reference oracle to validate the primitive behavior.
 */
const compression: CompressionProvider = {
    gzip(data: Uint8Array): Uint8Array {
        return new Uint8Array(gzipSync(data));
    },
    gunzip(data: Uint8Array): Uint8Array {
        return new Uint8Array(gunzipSync(data));
    },
    deflate(data: Uint8Array): Uint8Array {
        return new Uint8Array(deflateSync(data));
    },
    inflate(data: Uint8Array): Uint8Array {
        return new Uint8Array(inflateSync(data));
    },
    inflateRaw(data: Uint8Array): Uint8Array {
        return new Uint8Array(inflateRawSync(data));
    },
    brotliCompress(data: Uint8Array): Uint8Array {
        return new Uint8Array(brotliCompressSync(data));
    },
    brotliDecompress(data: Uint8Array): Uint8Array {
        return new Uint8Array(brotliDecompressSync(data));
    },
    decompress(data: Uint8Array, encoding: ContentEncoding): Uint8Array {
        switch (encoding) {
            case "gzip":
                return this.gunzip(data);
            case "deflate": {
                try {
                    return this.inflate(data);
                } catch {
                    return this.inflateRaw(data);
                }
            }
            case "br":
                return this.brotliDecompress(data);
            case "identity":
                return data;
            default:
                throw new UnsupportedEncodingError(`unsupported encoding: ${encoding}`);
        }
    },
};

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
        expect(() => compression.decompress(payload, "zstd" as ContentEncoding)).toThrow(
            UnsupportedEncodingError,
        );
    });
});
