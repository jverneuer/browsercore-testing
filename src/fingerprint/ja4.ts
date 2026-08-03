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
 * JA4H (the HTTP-layer sibling) is computed separately in {@link ./ja4h.ts}.
 *
 * Reference: https://github.com/FoxIO-LLC/JA4
 */

import { createHash } from "node:crypto";
import { Ja4ParseError } from "./ja4-errors.js";
import {
    EXT_ALPN,
    EXT_EC_POINT_FORMATS,
    EXT_SNI,
    EXT_SUPPORTED_GROUPS,
    GREASE_VALUES,
    hex4,
    readAlpnProtocols,
    readEcPointFormats,
    readSupportedGroups,
    tlsVersionLabel,
    uint16,
    uint24,
} from "./ja4-reader.js";

/**
 * Parsed fields from a ClientHello relevant to JA4.
 *
 * `cipherSuites` and `extensions` are the raw (non-GREASE) numeric values;
 * `supportedGroups` and `ecPointFormats` are the raw values from their
 * respective extensions; `alpnRaw` is the raw ALPN protocol string list.
 */
export interface Ja4ClientHello {
    readonly tlsVersion: string;
    /**
     * Raw numeric `client_version` code parsed from the ClientHello (e.g.
     * `0x0304` for TLS 1.3). Used by JA4_f so that byte-identical ClientHellos
     * produce the same fingerprint regardless of TLS-record wrapping.
     */
    readonly versionCode: number;
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

// Re-export the parse error so existing import sites (`from "./ja4.js"`) keep
// resolving after the type moved to `ja4-errors.ts`.
export { Ja4ParseError };

/** First 12 hex chars of the SHA-256 digest of `input`. */
export function sha256First12(input: string): string {
    return createHash("sha256").update(input).digest("hex").slice(0, 12);
}

/** ALPN code: first char of first ALPN + first char of last ALPN, or "00". */
function alpnCode(alpnRaw: string): string {
    if (alpnRaw.length === 0) {
        return "00";
    }
    const protocols = alpnRaw.split(",");
    const first = protocols[0] ?? "";
    const last = protocols.at(-1) ?? "";
    const a = first.length > 0 ? first[0] ?? "0" : "0";
    const b = last.length > 0 ? last[0] ?? "0" : "0";
    return `${a}${b}`.toLowerCase();
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
    const sessionIdLen = clientHello[pos];
    if (sessionIdLen === undefined) {
        throw new Ja4ParseError("ClientHello truncated at session id length");
    }
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
    const compLen = clientHello[pos];
    if (compLen === undefined) {
        throw new Ja4ParseError("ClientHello truncated at compression methods length");
    }
    pos += 1 + compLen;
    if (pos + 2 > end) {
        // No extensions present.
        return {
            tlsVersion: tlsVersionLabel(versionCode),
            versionCode,
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

        if (extType === EXT_SNI) {
            sniPresent = true;
        } else if (extType === EXT_SUPPORTED_GROUPS) {
            if (extLen >= 4) {
                supportedGroups.push(...readSupportedGroups(clientHello, pos));
            }
        } else if (extType === EXT_EC_POINT_FORMATS) {
            if (extLen >= 1) {
                ecPointFormats.push(...readEcPointFormats(clientHello, pos));
            }
        } else if (extType === EXT_ALPN && extLen >= 2) {
            alpnRaw = readAlpnProtocols(clientHello, pos);
        }
        // EXT_SUPPORTED_VERSIONS: JA4 uses the highest supported version from
        // this extension — no parsing needed here.

        pos += extLen;
    }

    return {
        tlsVersion: tlsVersionLabel(versionCode),
        versionCode,
        sniPresent,
        cipherSuites,
        extensions,
        supportedGroups,
        ecPointFormats,
        alpnRaw,
    };
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
    const sortedCiphers = [...hello.cipherSuites].sort((x, y) => x - y).map((s) => hex4(s)).join("");
    const b = sortedCiphers.length > 0 ? sha256First12(sortedCiphers) : "000000000000";

    // JA4_c: sorted extensions (excluding SNI=0, ALPN=16), 4-char hex.
    const filteredExts = hello.extensions
        .filter((e) => e !== EXT_SNI && e !== EXT_ALPN)
        .sort((x, y) => x - y)
        .map((e) => hex4(e))
        .join("");
    const c = filteredExts.length > 0 ? sha256First12(filteredExts) : "000000000000";

    // JA4_f: raw fields — version, ciphers, extensions, supported groups, ec.
    // Use the parsed client_version (`hello.versionCode`), NOT the first two
    // bytes of the buffer: those are the TLS record header (0x16 0x03) for a
    // record-wrapped hello and the handshake type byte (0x01 ...) for a bare
    // hello, so a bare and a record-wrapped ClientHello that are otherwise
    // byte-identical would otherwise hash differently.
    const raw = [
        hex4(hello.versionCode),
        hello.cipherSuites.map(hex4).join(""),
        hello.extensions.map(hex4).join(""),
        hello.supportedGroups.map(hex4).join(""),
        hello.ecPointFormats.map(hex4).join(""),
    ].join("");
    const f = sha256First12(raw);

    return { a, b, c, f, tag: `${a}_${b}_${c}_${f}` };
}
