/**
 * Node.js reference oracle.
 *
 * Wraps Node's built-in implementations (node:crypto, node:zlib, node:dns,
 * node:net, node:http, node:http2, node:tls) behind a uniform comparator surface
 * so our @network/* packages can be tested for EQUIVALENT observable behavior.
 *
 * Design rule: we compare against Node only for LAYERS WHERE NODE IS THE SPEC
 * REFERENCE — crypto primitives, DNS resolution, compression, and wire-format
 * serialization. We deliberately do NOT compare browser-fingerprint layers
 * (TLS ClientHello, HTTP/2 SETTINGS, default headers) against Node, because the
 * whole point of this project is to diverge from Node to match browsers. Those
 * are validated against browser golden captures elsewhere.
 *
 * Every method returns Node Buffer/values that our tests convert to Uint8Array
 * for comparison with our packages' Uint8Array-centric APIs.
 */

import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync, brotliCompressSync, brotliDecompressSync } from "node:zlib";
import { lookup as dnsLookup } from "node:dns";
import type { LookupOneOptions } from "node:dns";
import { deflateSync, inflateSync, constants as zlibConstants } from "node:zlib";
import { assertNever } from "../utils.js";

/** Normalize a Node Buffer / Uint8Array / readonly Uint8Array to a fresh Uint8Array. */
function toBytes(data: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(data);
}

/** Compare two byte arrays for equality (helper for one-off oracle checks). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

/** Which hash algorithm a primitive uses — branded union, no magic strings. */
export type HashAlgorithm = "sha256" | "sha384";
const HASH_LENGTHS = { sha256: 32, sha384: 48 } as const;

/** Validated HKDF/hash helpers that mirror the @network/crypto interface. */
export const nodeCrypto = {
    /** SHA-256 digest. Equivalent oracle for our `crypto.sha256`. */
    sha256(data: Uint8Array): Uint8Array {
        return toBytes(createHash("sha256").update(data).digest());
    },

    /** SHA-384 digest. Equivalent oracle for our `crypto.sha384`. */
    sha384(data: Uint8Array): Uint8Array {
        return toBytes(createHash("sha384").update(data).digest());
    },

    /**
     * HKDF extract+expand per RFC 5869. Equivalent oracle for our `crypto.hkdf`.
     * Uses node:crypto.hkdfSync under the hood.
     */
    hkdf(
        algorithm: HashAlgorithm,
        salt: Uint8Array,
        ikm: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Uint8Array {
        const algo = algorithm === "sha256" ? "sha256" : "sha384";
        return toBytes(
            hkdfSync(algo, ikm as Buffer, salt as Buffer, info as Buffer, length) as unknown as Uint8Array,
        );
    },

    /** HMAC. Equivalent oracle for our `crypto.hmac`. */
    hmac(algorithm: HashAlgorithm, key: Uint8Array, data: Uint8Array): Uint8Array {
        const algo = algorithm === "sha256" ? "sha256" : "sha384";
        return toBytes(createHmac(algo, key as Buffer).update(data).digest());
    },

    /** Cryptographically secure random bytes (length oracle). */
    randomBytes(length: number): Uint8Array {
        return toBytes(randomBytes(length));
    },

    /** Expected digest length for a given hash algorithm. */
    digestLength(algorithm: HashAlgorithm): number {
        return HASH_LENGTHS[algorithm];
    },
} as const;

/** DNS resolution oracle (mirrors our `resolveHost`). */
export const nodeDns = {
    /** Resolve a host to an address, matching our `resolveHost` semantics. */
    async lookup(
        host: string,
        ipv6: boolean,
    ): Promise<{ readonly address: string; readonly family: 4 | 6 }> {
        return new Promise((resolve, reject) => {
            const options: LookupOneOptions = { family: ipv6 ? 6 : 4 };
            dnsLookup(host, options, (err, address, family) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve({ address, family: (family as 4 | 6) });
            });
        });
    },
} as const;

/** Compression oracle (mirrors the future @network/compression interface). */
export const nodeZlib = {
    gzip(data: Uint8Array): Uint8Array {
        return toBytes(gzipSync(data));
    },
    gunzip(data: Uint8Array): Uint8Array {
        return toBytes(gunzipSync(data));
    },
    deflate(data: Uint8Array): Uint8Array {
        return toBytes(deflateSync(data));
    },
    inflate(data: Uint8Array): Uint8Array {
        return toBytes(inflateSync(data));
    },
    brotliCompress(data: Uint8Array): Uint8Array {
        return toBytes(brotliCompressSync(data));
    },
    brotliDecompress(data: Uint8Array): Uint8Array {
        return toBytes(brotliDecompressSync(data));
    },
    /** The zlib window bits constant, for comparing deflate framing decisions. */
    get zlibConstants(): typeof zlibConstants {
        return zlibConstants;
    },
} as const;

/**
 * Wire-format oracle for HTTP/1.1. Node's `http` module is the de-facto
 * reference for the on-the-wire request/response format (RFC 7230). We use it
 * to assert our serializer/parser produce bytes Node would accept and generate
 * the same wire layout.
 */
export const nodeHttp = {
    /**
     * Build the request-line + headers block exactly as Node's http client would
     * serialize them, so we can compare against our `serializeRequest`.
     * Body is appended verbatim by the caller.
     */
    serializeRequestLineAndHeaders(
        method: string,
        url: string,
        headers: ReadonlyMap<string, string>,
    ): Uint8Array {
        const lines: string[] = [`${method.toUpperCase()} ${url} HTTP/1.1`];
        for (const [name, value] of headers) {
            lines.push(`${name}: ${value}`);
        }
        // Node terminates the header section with a single blank line.
        return new TextEncoder().encode(`${lines.join("\r\n")}\r\n\r\n`);
    },
} as const;

/** Narrow an unknown thrown value to an Error (mirrors transport.ensure*). */
export function toError(e: unknown): Error {
    if (e instanceof Error) {
        return e;
    }
    return new Error(typeof e === "string" ? e : "unknown error");
}

/** Discriminated result of a reference comparison. */
export type CompareOutcome =
    | { readonly equal: true }
    | { readonly equal: false; readonly reason: string };

/** Generic byte-level comparison returning a discriminated outcome. */
export function compareBytesOutcome(a: Uint8Array, b: Uint8Array): CompareOutcome {
    if (bytesEqual(a, b)) {
        return { equal: true };
    }
    return {
        equal: false,
        reason: `length ${a.length} vs ${b.length}${
            a.length === b.length ? `, first diff at byte ${firstDiff(a, b)}` : ""
        }`,
    };
}

function firstDiff(a: Uint8Array, b: Uint8Array): number {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
        if (a[i] !== b[i]) {
            return i;
        }
    }
    return len;
}

void assertNever;
