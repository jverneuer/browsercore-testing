/**
 * Minimal ClientHello parser for e2e assertions.
 *
 * Parses the ClientHello *handshake message* (the output of
 * `@browsercore/tls` `buildClientHello`, or the handshake layer captured by a
 * sink server) into the structural fields the e2e suite asserts on:
 *   - offered cipher suites (IANA 2-byte codes, in wire order)
 *   - extension type list (in wire order, with raw data per extension)
 *   - legacy version, session id, compression methods
 *
 * The parser understands both the bare handshake message (first byte 0x01) and
 * the TLS record-wrapped form (first byte 0x16). It does NOT validate crypto —
 * it only deserializes layout, so it is a pure function of the input bytes.
 */

/** A parsed TLS extension: type code + opaque data (the body, no type/len prefix). */
export interface ParsedExtension {
    /** Extension type (IANA code, e.g. 0x0000 for SNI, 0x002b for supported_versions). */
    readonly type: number;
    /** Extension body (everything after the 4-byte type||len prefix). */
    readonly data: Uint8Array;
}

/** A parsed ClientHello handshake message. */
export interface ParsedClientHello {
    /** Legacy protocol version (uint16, always 0x0303 for TLS 1.3 ClientHellos). */
    readonly legacyVersion: number;
    /** client_random (32 bytes). */
    readonly random: Uint8Array;
    /** Session ID (variable length, often empty for TLS 1.3). */
    readonly sessionId: Uint8Array;
    /** Offered cipher suites as IANA 2-byte codes, in wire order. */
    readonly cipherSuites: readonly number[];
    /** Compression methods (variable length, usually [0x00]). */
    readonly compressionMethods: readonly number[];
    /** Extensions in wire order. */
    readonly extensions: readonly ParsedExtension[];
}

/** Read a big-endian uint16 at `offset` in `buf`. Throws if out of bounds. */
function uint16(buf: Uint8Array, offset: number): number {
    const hi = buf[offset];
    const lo = buf[offset + 1];
    if (hi === undefined || lo === undefined) {
        throw new RangeError(`uint16 read out of bounds at offset ${offset}`);
    }
    return (hi << 8) | lo;
}

/** Read a 24-bit big-endian integer at `offset` in `buf`. */
function uint24(buf: Uint8Array, offset: number): number {
    const b0 = buf[offset];
    const b1 = buf[offset + 1];
    const b2 = buf[offset + 2];
    if (b0 === undefined || b1 === undefined || b2 === undefined) {
        throw new RangeError(`uint24 read out of bounds at offset ${offset}`);
    }
    return (b0 << 16) | (b1 << 8) | b2;
}

/**
 * Parse a ClientHello handshake message into structured fields.
 *
 * Accepts either:
 *   - a TLS record (ContentType handshake 0x16) wrapping the handshake, or
 *   - a bare handshake message (handshake type 0x01).
 *
 * Throws {@link RangeError} on truncated input.
 */
export function parseClientHello(bytes: Uint8Array): ParsedClientHello {
    let pos: number;
    let handshakeLen: number;

    const first = bytes[0];
    if (first === undefined) {
        throw new RangeError("empty ClientHello buffer");
    }

    if (first === 0x16) {
        // TLS record wrapper: type(1) || version(2) || length(2) || handshake...
        if (bytes.length < 5) {
            throw new RangeError(`TLS record too short: ${bytes.length} < 5`);
        }
        pos = 5;
        const handshakeType = bytes[pos];
        if (handshakeType !== 0x01) {
            throw new RangeError(
                `expected ClientHello (0x01) inside TLS record, got 0x${(handshakeType ?? 0).toString(16)}`,
            );
        }
        handshakeLen = uint24(bytes, pos + 1);
        pos += 4; // skip handshake type(1) + length(3)
    } else if (first === 0x01) {
        // Bare handshake message.
        handshakeLen = uint24(bytes, 1);
        pos = 4;
    } else {
        throw new RangeError(
            `not a TLS record or ClientHello: first byte 0x${first.toString(16)}`,
        );
    }

    const end = pos + handshakeLen;
    if (end > bytes.length) {
        throw new RangeError(`handshake length ${handshakeLen} exceeds buffer ${bytes.length - pos}`);
    }

    // legacy_version(2) + random(32)
    if (pos + 34 > end) {
        throw new RangeError("ClientHello truncated before random");
    }
    const legacyVersion = uint16(bytes, pos);
    pos += 2;
    const random = bytes.subarray(pos, pos + 32);
    pos += 32;

    // session_id: length(1) + id
    const sessionIdLen = bytes[pos];
    if (sessionIdLen === undefined) {
        throw new RangeError("ClientHello truncated at session id length");
    }
    pos += 1;
    const sessionId = bytes.subarray(pos, pos + sessionIdLen);
    pos += sessionIdLen;

    // cipher_suites: length(2) || suites
    if (pos + 2 > end) {
        throw new RangeError("ClientHello truncated at cipher suites length");
    }
    const cipherSuitesLen = uint16(bytes, pos);
    pos += 2;
    if (pos + cipherSuitesLen > end) {
        throw new RangeError("ClientHello truncated in cipher suites");
    }
    const cipherSuites: number[] = [];
    for (let i = 0; i < cipherSuitesLen; i += 2) {
        cipherSuites.push(uint16(bytes, pos + i));
    }
    pos += cipherSuitesLen;

    // compression_methods: length(1) || methods
    const compLen = bytes[pos];
    if (compLen === undefined) {
        throw new RangeError("ClientHello truncated at compression methods length");
    }
    pos += 1;
    const compressionMethods: number[] = [];
    for (let i = 0; i < compLen; i++) {
        const m = bytes[pos + i];
        if (m === undefined) {
            throw new RangeError("ClientHello truncated in compression methods");
        }
        compressionMethods.push(m);
    }
    pos += compLen;

    // extensions: length(2) || extensions
    const extensions: ParsedExtension[] = [];
    if (pos + 2 <= end) {
        const extensionsLen = uint16(bytes, pos);
        pos += 2;
        const extEnd = pos + extensionsLen;
        if (extEnd > end) {
            throw new RangeError("ClientHello truncated in extensions block");
        }
        while (pos < extEnd) {
            if (pos + 4 > extEnd) {
                throw new RangeError("ClientHello extension header truncated");
            }
            const type = uint16(bytes, pos);
            const dataLen = uint16(bytes, pos + 2);
            pos += 4;
            if (pos + dataLen > extEnd) {
                throw new RangeError(`ClientHello extension 0x${type.toString(16)} data truncated`);
            }
            const data = bytes.subarray(pos, pos + dataLen);
            pos += dataLen;
            extensions.push({ type, data });
        }
    }

    return {
        legacyVersion,
        random,
        sessionId,
        cipherSuites,
        compressionMethods,
        extensions,
    };
}

/**
 * Find the first extension of a given type in a parsed ClientHello.
 * Returns undefined if absent.
 */
export function findExtension(
    hello: ParsedClientHello,
    type: number,
): ParsedExtension | undefined {
    return hello.extensions.find((ext) => ext.type === type);
}

/**
 * Decode the SNI server_name_list (extension 0x0000) into hostnames.
 *
 * RFC 6066 §3: server_name_list = length(2) || entries, each entry =
 * name_type(1) || length(2) || name. We only handle name_type=0 (host_name).
 */
export function decodeSni(hello: ParsedClientHello): readonly string[] {
    const ext = findExtension(hello, 0x0000);
    if (ext === undefined || ext.data.length < 2) {
        return [];
    }
    const names: string[] = [];
    let pos = 0;
    const listLen = uint16(ext.data, pos);
    pos += 2;
    const end = pos + listLen;
    while (pos + 3 <= end) {
        const nameType = ext.data[pos]!;
        const nameLen = uint16(ext.data, pos + 1);
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
 */
export function decodeSupportedVersions(hello: ParsedClientHello): readonly number[] {
    const ext = findExtension(hello, 0x002b);
    if (ext === undefined || ext.data.length < 1) {
        return [];
    }
    const versions: number[] = [];
    const listLen = ext.data[0];
    if (listLen === undefined) {
        return [];
    }
    let pos = 1;
    for (let i = 0; i < listLen; i += 2) {
        if (pos + 1 >= ext.data.length) {
            break;
        }
        versions.push(uint16(ext.data, pos));
        pos += 2;
    }
    return versions;
}

/**
 * Decode the ALPN extension (0x0010) into the offered protocol names.
 *
 * RFC 7301: the body is a length-prefixed list of length-prefixed UTF-8 names.
 */
export function decodeAlpn(hello: ParsedClientHello): readonly string[] {
    const ext = findExtension(hello, 0x0010);
    if (ext === undefined || ext.data.length < 2) {
        return [];
    }
    const protocols: string[] = [];
    let pos = 0;
    const listLen = uint16(ext.data, pos);
    pos += 2;
    const end = pos + listLen;
    while (pos < end) {
        const protoLen = ext.data[pos];
        if (protoLen === undefined) {
            break;
        }
        pos += 1;
        if (pos + protoLen > end) {
            break;
        }
        protocols.push(new TextDecoder().decode(ext.data.subarray(pos, pos + protoLen)));
        pos += protoLen;
    }
    return protocols;
}
