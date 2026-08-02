/**
 * JA4 TLS fingerprint (docs/TEST-SUITE.md, Category 4).
 *
 * JA4 is a multi-part fingerprint family that captures significantly more signal
 * than JA3. We compute the standard four-part TLS fingerprint:
 *
 *   JA4_a   connection prefix  — transport, TLS version, SNI flag, cipher count,
 *                                extension count, ALPN code.
 *   JA4_b   cipher-suite hash  — sorted non-GREASE cipher suites, SHA-256,
 *                                first 12 hex chars.
 *   JA4_c   extension hash      — sorted non-GREASE extensions (excluding SNI +
 *                                ALPN), SHA-256, first 12 hex chars.
 *   JA4_f   raw-fields hash    — TLS version, ciphers, extensions, supported
 *                                groups, EC point formats, SHA-256, first 12 hex.
 *
 * The concatenated `JA4_a_JA4_b_JA4_c_JA4_f` string is the canonical JA4 tag.
 *
 * JA4H (the HTTP-layer sibling) is computed separately by {@link computeJa4h}
 * from method/version/headers/cookies — it is the HTTP analogue used by the
 * reference provider to fingerprint a captured request.
 *
 * Reference: https://github.com/FoxIO-LLC/JA4
 */

import { createHash } from "node:crypto";

/** Reasons a ClientHello cannot be parsed into a JA4 input. */
export class Ja4ParseError extends Error {
    public readonly kind = "Ja4ParseError" as const;
    constructor(message: string) {
        super(message);
        this.name = "Ja4ParseError";
    }
}

/**
 * Parsed fields from a ClientHello relevant to JA4.
 *
 * `cipherSuites` and `extensions` are the raw (non-GREASE) numeric values;
 * `supportedGroups` and `ecPointFormats` are the raw values from their
 * respective extensions; `alpnRaw` is the raw ALPN protocol string list.
 */
export interface Ja4ClientHello {
    readonly tlsVersion: string;
    readonly sniPresent: boolean;
    readonly cipherSuites: readonly number[];
    readonly extensions: readonly number[];
    readonly supportedGroups: readonly number[];
    readonly ecPointFormats: readonly number[];
    readonly alpnRaw: string;
}

/** The four computed JA4 parts. */
export interface Ja4Fingerprint {
    readonly a: string;
    readonly b: string;
    readonly c: string;
    readonly f: string;
    /** Canonical `JA4_a_JA4_b_JA4_c_JA4_f` tag. */
    readonly tag: string;
}

/** The three computed JA4H parts. */
export interface Ja4hFingerprint {
    readonly a: string;
    readonly b: string;
    readonly c: string;
    readonly d: string;
    /** Canonical `JA4H_a_JA4H_b_JA4H_c_JA4H_d` tag. */
    readonly tag: string;
}

/** GREASE values per RFC 8701 — these are reserved and must be ignored. */
const GREASE_VALUES: ReadonlySet<number> = new Set([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/** TLS extension type numbers we special-case when parsing. */
const EXT_SNI = 0x0000;
const EXT_SUPPORTED_GROUPS = 0x000a;
const EXT_EC_POINT_FORMATS = 0x000b;
const EXT_ALPN = 0x0010;
const EXT_SUPPORTED_VERSIONS = 0x002b;

/** TLS protocol-version codes → human-readable version string. */
const TLS_VERSIONS = new Map<number, string>([
    [0x0304, "13"],
    [0x0303, "12"],
    [0x0302, "11"],
    [0x0301, "10"],
    [0x0300, "09"],
]);

/** Read a big-endian uint16 at `offset` in `buf` (unchecked — caller bounds). */
function uint16(buf: Uint8Array, offset: number): number {
    return (buf[offset]! << 8) | buf[offset + 1]!;
}

/** Read a 24-bit big-endian integer at `offset` in `buf`. */
function uint24(buf: Uint8Array, offset: number): number {
    return (buf[offset]! << 16) | (buf[offset + 1]! << 8) | buf[offset + 2]!;
}

/** Format a number as a 4-char lowercase hex string (`0x1a2b` → `"1a2b"`). */
function hex4(value: number): string {
    return value.toString(16).padStart(4, "0");
}

/** First 12 hex chars of the SHA-256 digest of `input`. */
function sha256First12(input: string): string {
    return createHash("sha256").update(input).digest("hex").slice(0, 12);
}

/**
 * Parse a TLS ClientHello (either wrapped in a TLS record or bare) into the
 * fields JA4 needs. Throws {@link Ja4ParseError} on malformed input.
 */
export function parseJa4ClientHello(clientHello: Uint8Array): Ja4ClientHello {
    let pos: number;
    let handshakeLen: number;

    if (clientHello.length === 0) {
        throw new Ja4ParseError("ClientHello is empty");
    }

    // TLS record wrapper: ContentType handshake (0x16) + version(2) + length(2).
    if (clientHello[0] === 0x16) {
        if (clientHello.length < 5) {
            throw new Ja4ParseError("TLS record too short");
        }
        pos = 5;
        if (clientHello[pos] !== 0x01) {
            throw new Ja4ParseError(
                `Expected ClientHello (0x01) at record+0, got 0x${clientHello[pos]?.toString(16)}`,
            );
        }
        handshakeLen = uint24(clientHello, pos + 1);
        pos += 4;
        const available = clientHello.length - pos;
        if (handshakeLen > available) {
            throw new Ja4ParseError(
                `Handshake length ${handshakeLen} exceeds available ${available} bytes`,
            );
        }
    } else if (clientHello[0] === 0x01) {
        // Bare handshake.
        if (clientHello.length < 4) {
            throw new Ja4ParseError("Bare ClientHello too short");
        }
        handshakeLen = uint24(clientHello, 1);
        pos = 4;
        const available = clientHello.length - pos;
        if (handshakeLen > available) {
            throw new Ja4ParseError(
                `Handshake length ${handshakeLen} exceeds available ${available} bytes`,
            );
        }
    } else {
        throw new Ja4ParseError(
            `Not a TLS record or ClientHello (first byte 0x${clientHello[0]?.toString(16)})`,
        );
    }

    const end = pos + handshakeLen;
    if (pos + 2 > end) {
        throw new Ja4ParseError("ClientHello too short for version");
    }

    // client_version(2)
    const versionCode = uint16(clientHello, pos);
    pos += 2;
    // random(32)
    pos += 32;
    if (pos > end) {
        throw new Ja4ParseError("ClientHello truncated before session id");
    }
    // session_id(variable)
    const sessionIdLen = clientHello[pos]!;
    pos += 1 + sessionIdLen;
    if (pos + 2 > end) {
        throw new Ja4ParseError("ClientHello truncated before cipher suites");
    }
    // cipher_suites(variable)
    const cipherSuitesLen = uint16(clientHello, pos);
    pos += 2;
    if (pos + cipherSuitesLen > end) {
        throw new Ja4ParseError("ClientHello truncated in cipher suites");
    }
    const cipherSuites: number[] = [];
    for (let i = 0; i + 1 < cipherSuitesLen; i += 2) {
        const suite = uint16(clientHello, pos + i);
        if (!GREASE_VALUES.has(suite)) {
            cipherSuites.push(suite);
        }
    }
    pos += cipherSuitesLen;
    if (pos + 1 > end) {
        throw new Ja4ParseError("ClientHello truncated before compression methods");
    }
    // compression_methods(variable)
    const compLen = clientHello[pos]!;
    pos += 1 + compLen;
    if (pos + 2 > end) {
        // No extensions present.
        return {
            tlsVersion: TLS_VERSIONS.get(versionCode) ?? versionCode.toString(16).padStart(2, "0"),
            sniPresent: false,
            cipherSuites,
            extensions: [],
            supportedGroups: [],
            ecPointFormats: [],
            alpnRaw: "",
        };
    }
    // extensions(variable)
    const extensionsLen = uint16(clientHello, pos);
    pos += 2;
    const extensionsEnd = pos + extensionsLen;

    const extensions: number[] = [];
    let sniPresent = false;
    const supportedGroups: number[] = [];
    const ecPointFormats: number[] = [];
    let alpnRaw = "";

    while (pos + 4 <= extensionsEnd) {
        const extType = uint16(clientHello, pos);
        const extLen = uint16(clientHello, pos + 2);
        pos += 4;

        if (!GREASE_VALUES.has(extType)) {
            extensions.push(extType);
        }

        switch (extType) {
            case EXT_SNI:
                sniPresent = true;
                break;
            case EXT_SUPPORTED_GROUPS:
                if (extLen >= 4) {
                    const listLen = uint16(clientHello, pos);
                    for (let i = 0; i + 1 < listLen; i += 2) {
                        const group = uint16(clientHello, pos + 2 + i);
                        if (!GREASE_VALUES.has(group)) {
                            supportedGroups.push(group);
                        }
                    }
                }
                break;
            case EXT_EC_POINT_FORMATS:
                if (extLen >= 1) {
                    const listLen = clientHello[pos]!;
                    for (let i = 0; i < listLen; i++) {
                        ecPointFormats.push(clientHello[pos + 1 + i]!);
                    }
                }
                break;
            case EXT_ALPN:
                if (extLen >= 2) {
                    const listLen = uint16(clientHello, pos);
                    let cursor = pos + 2;
                    const protocols: string[] = [];
                    const listEnd = cursor + listLen;
                    while (cursor < listEnd) {
                        const protoLen = clientHello[cursor]!;
                        cursor += 1;
                        protocols.push(
                            new TextDecoder().decode(clientHello.subarray(cursor, cursor + protoLen)),
                        );
                        cursor += protoLen;
                    }
                    alpnRaw = protocols.join(",");
                }
                break;
            case EXT_SUPPORTED_VERSIONS:
                // JA4 uses the highest supported version from this extension.
                break;
            default:
                break;
        }

        pos += extLen;
    }

    return {
        tlsVersion: TLS_VERSIONS.get(versionCode) ?? versionCode.toString(16).padStart(2, "0"),
        sniPresent,
        cipherSuites,
        extensions,
        supportedGroups,
        ecPointFormats,
        alpnRaw,
    };
}

/** ALPN code: first char of first ALPN + first char of last ALPN, or "00". */
function alpnCode(alpnRaw: string): string {
    if (alpnRaw.length === 0) {
        return "00";
    }
    const protocols = alpnRaw.split(",");
    const first = protocols[0] ?? "";
    const last = protocols[protocols.length - 1] ?? "";
    const a = first.length > 0 ? first[0]! : "0";
    const b = last.length > 0 ? last[0]! : "0";
    return `${a}${b}`.toLowerCase();
}

/**
 * Compute the canonical JA4 tag (`JA4_a_JA4_b_JA4_c_JA4_f`) from a ClientHello.
 *
 * This is the string form used by the public API (index.ts) and the reference
 * provider. Use {@link computeJa4Fingerprint} when you need the parts.
 */
export function computeJa4(clientHello: Uint8Array): string {
    return computeJa4Fingerprint(clientHello).tag;
}

/**
 * Compute the four-part JA4 TLS fingerprint from a ClientHello buffer.
 *
 * Returns the individual parts plus the canonical `JA4_a_JA4_b_JA4_c_JA4_f`
 * tag. The caller can use any part — comparison is typically done against the
 * full tag or against JA4_a (the connection prefix) for grouping.
 */
export function computeJa4Fingerprint(clientHello: Uint8Array): Ja4Fingerprint {
    const hello = parseJa4ClientHello(clientHello);

    // JA4_a: t{ciphers:02d}{exts:02d}{sni_flag}{version}{alpn}
    const sniFlag = hello.sniPresent ? "d" : "i";
    const a = `t${hello.cipherSuites.length.toString().padStart(2, "0")}${hello.extensions.length
        .toString()
        .padStart(2, "0")}${sniFlag}${hello.tlsVersion}${alpnCode(hello.alpnRaw)}`;

    // JA4_b: sorted cipher suites, 4-char hex, SHA-256, first 12 hex.
    const sortedCiphers = [...hello.cipherSuites].sort((x, y) => x - y).map(hex4).join("");
    const b = sortedCiphers.length > 0 ? sha256First12(sortedCiphers) : "000000000000";

    // JA4_c: sorted extensions (excluding SNI=0, ALPN=16), 4-char hex.
    const filteredExts = hello.extensions
        .filter((e) => e !== EXT_SNI && e !== EXT_ALPN)
        .sort((x, y) => x - y)
        .map(hex4)
        .join("");
    const c = filteredExts.length > 0 ? sha256First12(filteredExts) : "000000000000";

    // JA4_f: raw fields — version, ciphers, extensions, supported groups, ec.
    const raw = [
        hex4(clientHello.length > 1 ? uint16(clientHello, 0) : 0),
        hello.cipherSuites.map(hex4).join(""),
        hello.extensions.map(hex4).join(""),
        hello.supportedGroups.map(hex4).join(""),
        hello.ecPointFormats.map(hex4).join(""),
    ].join("");
    const f = sha256First12(raw);

    return { a, b, c, f, tag: `${a}_${b}_${c}_${f}` };
}

/**
 * HTTP request fields needed to compute a JA4H fingerprint.
 *
 * Only the parts JA4H inspects are required — method, HTTP version, header
 * names (in order), cookies, and the Accept-Language prefix.
 */
export interface Ja4hRequest {
    readonly method: "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH";
    readonly httpVersion: "1.1" | "2" | "3";
    /** Header names in the order they are serialized (lowercased). */
    readonly headerNames: readonly string[];
    /** Cookie name=value pairs (as they appear in the Cookie header). */
    readonly cookies: readonly string[];
    /** The Accept-Language header value (only its 4-char prefix is used). */
    readonly acceptLanguage?: string;
}

/**
 * Compute the four-part JA4H HTTP fingerprint from a captured request.
 *
 * Format: `JA4H_a_JA4H_b_JA4H_c_JA4H_d` where:
 * - JA4H_a: `{method:02s}{version}{has_cookies:d}{has_referer:d}{header_count:02d}{lang_prefix}`
 * - JA4H_b: sorted cookie name=value pairs, SHA-256, first 12 hex.
 * - JA4H_c: sorted cookie names, SHA-256, first 12 hex.
 * - JA4H_d: sorted header names (excluding cookie), SHA-256, first 12 hex.
 */
export function computeJa4h(request: Ja4hRequest): Ja4hFingerprint {
    const methodCode = request.method.slice(0, 2).toLowerCase();
    const versionCode =
        request.httpVersion === "1.1"
            ? "11"
            : request.httpVersion === "2"
              ? "02"
              : request.httpVersion === "3"
                ? "03"
                : "00";
    const hasCookies = request.cookies.length > 0 ? "c" : "n";
    const hasReferer = request.headerNames.some((h) => h === "referer") ? "r" : "n";
    const headerCount = request.headerNames.length.toString().padStart(2, "0");
    const langPrefix = (request.acceptLanguage ?? "").slice(0, 4).padEnd(4, "0").toLowerCase();

    const a = `${methodCode}${versionCode}${hasCookies}${hasReferer}${headerCount}${langPrefix}`;

    const sortedCookies = [...request.cookies].sort().join(",");
    const b = sortedCookies.length > 0 ? sha256First12(sortedCookies) : "000000000000";

    const sortedCookieNames = [...request.cookies]
        .map((c) => c.split("=")[0] ?? "")
        .filter((n) => n.length > 0)
        .sort()
        .join(",");
    const c = sortedCookieNames.length > 0 ? sha256First12(sortedCookieNames) : "000000000000";

    const sortedHeaders = [...request.headerNames]
        .filter((h) => h !== "cookie")
        .sort()
        .join(",");
    const d = sortedHeaders.length > 0 ? sha256First12(sortedHeaders) : "000000000000";

    return { a, b, c, d, tag: `${a}_${b}_${c}_${d}` };
}
