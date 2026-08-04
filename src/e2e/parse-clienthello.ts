/**
 * Minimal TLS 1.2+ ClientHello parser for the E2E TLS sink server.
 *
 * Parses the wire bytes a sink captured *before* TLS parsing, exposing the
 * fields the e2e test matrix (T2–T9 in the plan) asserts on: cipher suites,
 * extension types / order, ALPN protocols, SNI hostname, supported_versions.
 *
 * The parser is intentionally lenient about trailing data — it reads only the
 * ClientHello body and stops. It does NOT validate cryptographic integrity;
 * that is the handshake's job. All offsets are computed dynamically from the
 * parsed structure (never hardcoded) so the same code works whether the input
 * is a bare handshake message or a full TLS record (the caller strips the
 * 5-byte record header via {@link parseClientHello}).
 *
 * This module merges the original minimal parser (shipped on `main`) with the
 * E2E TLS sink server infrastructure (from `feat/e2e-sink`): the `EXT` constant
 * table, `ClientHelloParseError`, richer offset/length metadata on
 * {@link ParsedClientHello}, and GREASE utilities from the sink branch are
 * retained alongside the `decodeSni`, `decodeAlpn`, `decodeSupportedVersions`
 * accessors from `main`.
 */

// --- Parsed types -------------------------------------------------------

/** A single parsed extension: type wire value + raw data bytes. */
export interface ParsedExtension {
    /** Extension type (IANA wire value, e.g. 0x0000 for SNI). */
    readonly type: number;
    /** Length of `data` on the wire (excludes type + length prefix). */
    readonly length: number;
    /** Raw extension data (empty for zero-length extensions). */
    readonly data: Uint8Array;
}

/**
 * Fully parsed ClientHello.
 *
 * Byte offsets are captured so tests can map a field back to its wire position
 * when reporting divergence (without hardcoding offsets). `cipherSuites` and
 * `compressionMethods` are exposed as flat numeric arrays for direct
 * iteration / `.filter()` / `.some()` consumption (see the e2e ClientHello
 * suite on `main`).
 */
export interface ParsedClientHello {
    /** Starting offset of the handshake type byte within the input. */
    readonly handshakeTypeOffset: number;
    /** Handshake type — always 0x01 (ClientHello). */
    readonly handshakeType: number;
    /** Handshake body length (24-bit). */
    readonly handshakeLength: number;
    /** Legacy protocol version (usually 0x0303). */
    readonly legacyVersion: number;
    /** 32-byte client random. */
    readonly random: Uint8Array;
    /** Session ID (empty when not resuming). */
    readonly sessionId: Uint8Array;
    /** Offered cipher suites as IANA 2-byte codes, in wire order (including GREASE). */
    readonly cipherSuites: readonly number[];
    /** Compression methods (variable length, usually [0x00]). */
    readonly compressionMethods: readonly number[];
    /** Extensions in wire order. Empty if the client sent none. */
    readonly extensions: readonly ParsedExtension[];
    /** Total bytes consumed from the input (handshake type + length + body). */
    readonly totalLength: number;
}

// --- Extension-type constants (IANA) ------------------------------------

export const EXT = {
    SERVER_NAME: 0x0000,
    SUPPORTED_VERSIONS: 0x002b,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION: 0x0010,
    KEY_SHARE: 0x0033,
    SUPPORTED_GROUPS: 0x000a,
    PSK_KEY_EXCHANGE_MODES: 0x002d,
    SIGNATURE_ALGORITHMS: 0x000d,
} as const;
export type ExtensionTypeValue = (typeof EXT)[keyof typeof EXT];

// --- Errors -------------------------------------------------------------

/** Thrown when the input is too short to be a valid ClientHello. */
export class ClientHelloParseError extends Error {
    public readonly kind = "ClientHelloParseError" as const;
    public readonly byteOffset: number;
    public override readonly cause: Error | undefined;

    constructor(message: string, byteOffset: number, options?: { cause?: Error }) {
        super(message, options);
        this.name = "ClientHelloParseError";
        this.byteOffset = byteOffset;
        this.cause = options?.cause;
    }
}

// --- Parser helpers -----------------------------------------------------

/** Read a big-endian uint16 at `offset`. */
function readUint16(buf: Uint8Array, offset: number): number {
    return (buf[offset]! << 8) | buf[offset + 1]!;
}

/**
 * Parse a TLS record header. Returns the offset of the handshake message that
 * follows (i.e. 5 for a well-formed record) or `null` if the input does not
 * start with a Handshake record (content type 0x16).
 *
 * Callers that already stripped the record header can pass the raw handshake
 * message directly to {@link parseClientHello}.
 */
export function peekRecordHeader(buf: Uint8Array): number | null {
    if (buf.length < 5) return null;
    const contentType = buf[0]!;
    if (contentType !== 0x16) return null; // Not a Handshake record.
    // Bytes 1-2: record version (0x0303). Bytes 3-4: fragment length.
    return 5;
}

/**
 * Parse a ClientHello from raw wire bytes.
 *
 * Accepts either a full TLS Handshake record (5-byte header + handshake
 * message) or a bare handshake message (type + 24-bit length + body). The
 * function auto-detects the record header by content type.
 *
 * Distinct from the JA3 `parseClientHello` in `@browsercore/testing`'s
 * fingerprint module (which returns JA3 segments). This parser returns the
 * full structural breakdown (cipher suites, extensions, SNI, ALPN, etc.) for
 * the e2e test matrix.
 *
 * @param buf Raw bytes as seen on the wire.
 * @throws {ClientHelloParseError} if the input is malformed or truncated.
 */
export function parseClientHello(buf: Uint8Array): ParsedClientHello {
    let o = 0;
    const recordOffset = peekRecordHeader(buf);
    if (recordOffset !== null) {
        o = recordOffset; // skip 5-byte record header.
    }

    const start = o;
    if (o + 4 > buf.length) {
        throw new ClientHelloParseError(
            `ClientHello truncated at handshake header (need 4 bytes at offset ${o}, have ${buf.length - o})`,
            o,
        );
    }

    const handshakeType = buf[o]!;
    if (handshakeType !== 0x01) {
        throw new ClientHelloParseError(
            `Expected handshake type 0x01 (ClientHello), got 0x${handshakeType.toString(16).padStart(2, "0")}`,
            o,
        );
    }
    const handshakeLength = (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!;
    o += 4;

    const bodyEnd = o + handshakeLength;
    if (bodyEnd > buf.length) {
        throw new ClientHelloParseError(
            `ClientHello body truncated (need ${handshakeLength} bytes, have ${buf.length - o})`,
            o,
        );
    }

    // legacy_version (2) + random (32).
    if (o + 34 > bodyEnd) {
        throw new ClientHelloParseError("ClientHello too short for legacy_version + random", o);
    }
    const legacyVersion = readUint16(buf, o);
    o += 2;
    const random = buf.subarray(o, o + 32);
    o += 32;

    // session_id: length-prefixed.
    const sessionIdLen = buf[o]!;
    o += 1;
    if (o + sessionIdLen > bodyEnd) {
        throw new ClientHelloParseError("session_id extends past ClientHello body", o);
    }
    const sessionId = buf.subarray(o, o + sessionIdLen);
    o += sessionIdLen;

    // cipher_suites: 2-byte length prefix + (len/2) suites.
    if (o + 2 > bodyEnd) {
        throw new ClientHelloParseError("cipher_suites length truncated", o);
    }
    const csLen = readUint16(buf, o);
    o += 2;
    if (o + csLen > bodyEnd || csLen % 2 !== 0) {
        throw new ClientHelloParseError("cipher_suites body truncated or odd length", o);
    }
    const suites: number[] = [];
    for (let i = 0; i < csLen; i += 2) {
        suites.push(readUint16(buf, o + i));
    }
    o += csLen;

    // compression_methods: 1-byte length prefix + methods.
    const compLen = buf[o]!;
    o += 1;
    if (o + compLen > bodyEnd) {
        throw new ClientHelloParseError("compression_methods truncated", o);
    }
    const methods: number[] = [];
    for (let i = 0; i < compLen; i++) {
        methods.push(buf[o + i]!);
    }
    o += compLen;

    // extensions: 2-byte length prefix + extension list (may be absent).
    const extensions: ParsedExtension[] = [];
    if (o + 2 <= bodyEnd) {
        const extLen = readUint16(buf, o);
        o += 2;
        const extEnd = o + extLen;
        if (extEnd > bodyEnd) {
            throw new ClientHelloParseError("extensions block truncated", o);
        }
        while (o + 4 <= extEnd) {
            const extType = readUint16(buf, o);
            const extLen2 = readUint16(buf, o + 2);
            o += 4;
            if (o + extLen2 > extEnd) {
                throw new ClientHelloParseError(
                    `extension 0x${extType.toString(16).padStart(4, "0")} data truncated`,
                    o,
                );
            }
            extensions.push({ type: extType, length: extLen2, data: buf.subarray(o, o + extLen2) });
            o += extLen2;
        }
        o = extEnd;
    }

    void o; // body fully consumed; trailing bytes (next record) ignored.

    return {
        handshakeTypeOffset: start,
        handshakeType,
        handshakeLength,
        legacyVersion,
        random,
        sessionId,
        cipherSuites: suites,
        compressionMethods: methods,
        extensions,
        totalLength: bodyEnd - start,
    };
}

/**
 * Wire-compatible alias of {@link parseClientHello}. Exported for callers that
 * prefer the `parseClientHelloWire` name used by the E2E TLS sink server.
 */
export const parseClientHelloWire = parseClientHello;

// --- Extension accessors ------------------------------------------------

/**
 * Find the first extension of the given type. Returns `undefined` if absent.
 */
export function findExtension(
    hello: ParsedClientHello,
    type: number,
): ParsedExtension | undefined {
    return hello.extensions.find((e) => e.type === type);
}

// --- parse* accessors (feat/e2e-sink naming) ----------------------------

/**
 * Parse the SNI extension (type 0x0000) and return the first hostname.
 *
 * Layout: server_name_list_len(2) + entries. Each entry: name_type(1) +
 * name_len(2) + name. name_type 0 = host_name.
 */
export function parseSniHostname(hello: ParsedClientHello): string | null {
    const ext = findExtension(hello, EXT.SERVER_NAME);
    if (ext === undefined || ext.data.length < 3) return null;
    let o = 0;
    const listLen = readUint16(ext.data, o);
    o += 2;
    void listLen;
    while (o + 3 <= ext.data.length) {
        const nameType = ext.data[o]!;
        const nameLen = readUint16(ext.data, o + 1);
        o += 3;
        if (o + nameLen > ext.data.length) return null;
        if (nameType === 0) {
            return new TextDecoder().decode(ext.data.subarray(o, o + nameLen));
        }
        o += nameLen;
    }
    return null;
}

/**
 * Parse the ALPN extension (type 0x0010) and return the offered protocols in
 * wire order.
 *
 * Layout: protocol_list_len(2) + entries. Each entry: name_len(1) + name.
 */
export function parseAlpnProtocols(hello: ParsedClientHello): readonly string[] {
    const ext = findExtension(hello, EXT.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    if (ext === undefined || ext.data.length < 1) return [];
    let o = 0;
    const listLen = readUint16(ext.data, o);
    o += 2;
    void listLen;
    const protocols: string[] = [];
    while (o + 1 <= ext.data.length) {
        const nameLen = ext.data[o]!;
        o += 1;
        if (o + nameLen > ext.data.length) break;
        protocols.push(new TextDecoder().decode(ext.data.subarray(o, o + nameLen)));
        o += nameLen;
    }
    return protocols;
}

/**
 * Parse the supported_versions extension (type 0x002b) and return the offered
 * versions in wire order.
 *
 * RFC 8446 §4.2.1.1: the client body is a 1-byte length-prefixed list of
 * uint16 wire versions (`versions<2..254>`). The length byte counts the
 * number of *bytes* of version data (always even), so the number of versions
 * is `length / 2`.
 */
export function parseSupportedVersions(hello: ParsedClientHello): readonly number[] {
    const ext = findExtension(hello, EXT.SUPPORTED_VERSIONS);
    if (ext === undefined || ext.data.length < 1) return [];
    const versionsLen = ext.data[0]!;
    const versions: number[] = [];
    let o = 1;
    while (o + 2 <= 1 + versionsLen && o + 2 <= ext.data.length) {
        versions.push(readUint16(ext.data, o));
        o += 2;
    }
    return versions;
}

// --- decode* accessors (main branch naming) -----------------------------

/**
 * Decode the SNI server_name_list (extension 0x0000) into hostnames.
 *
 * RFC 6066 §3: server_name_list = length(2) || entries, each entry =
 * name_type(1) || length(2) || name. We only handle name_type=0 (host_name).
 *
 * Returns all hostnames in the list. Use {@link parseSniHostname} for the
 * first one only.
 */
export function decodeSni(hello: ParsedClientHello): readonly string[] {
    const ext = findExtension(hello, 0x0000);
    if (ext === undefined || ext.data.length < 2) {
        return [];
    }
    const names: string[] = [];
    let pos = 0;
    const listLen = readUint16(ext.data, pos);
    pos += 2;
    const end = pos + listLen;
    while (pos + 3 <= end) {
        const nameType = ext.data[pos]!;
        const nameLen = readUint16(ext.data, pos + 1);
        pos += 3;
        if (pos + nameLen > end) {
            break;
        }
        const nameBytes = ext.data.subarray(pos, pos + nameLen);
        pos += nameLen;
        if (nameType === 0) {
            names.push(new TextDecoder().decode(nameBytes));
        }
    }
    return names;
}

/**
 * Decode the supported_versions extension (0x002b) for a client ClientHello.
 *
 * RFC 8446 §4.2.1: the client body is a length-prefixed list of uint16 wire
 * versions. Returns the versions in wire order.
 *
 * Compatible alias of {@link parseSupportedVersions}.
 */
export function decodeSupportedVersions(hello: ParsedClientHello): readonly number[] {
    return parseSupportedVersions(hello);
}

/**
 * Decode the ALPN extension (0x0010) into the offered protocol names.
 *
 * RFC 7301: the body is a length-prefixed list of length-prefixed UTF-8 names.
 *
 * Compatible alias of {@link parseAlpnProtocols}.
 */
export function decodeAlpn(hello: ParsedClientHello): readonly string[] {
    return parseAlpnProtocols(hello);
}

// --- GREASE sentinel detection ------------------------------------------

/**
 * The 16 GREASE sentinel values per RFC 8701: both bytes identical, low nibble
 * 0xA. Used to detect / strip GREASE from cipher + extension assertions.
 */
export const GREASE_SENTINELS: readonly number[] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

const GREASE_SET = new Set<number>(GREASE_SENTINELS);

/** True if the given 16-bit wire value is a GREASE sentinel. */
export function isGrease(value: number): boolean {
    return GREASE_SET.has(value);
}

/** Return the cipher suites with GREASE sentinels removed. */
export function nonGreaseCipherSuites(hello: ParsedClientHello): readonly number[] {
    return hello.cipherSuites.filter((s) => !isGrease(s));
}

/** Return the extension types with GREASE sentinels removed. */
export function nonGreaseExtensionTypes(hello: ParsedClientHello): readonly number[] {
    return hello.extensions.filter((e) => !isGrease(e.type)).map((e) => e.type);
}
