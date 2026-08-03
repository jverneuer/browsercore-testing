/**
 * Low-level TLS ClientHello byte readers shared by JA4 computation.
 *
 * Factored out of `ja4.ts` so the fingerprint module stays focused on the
 * JA4 spec (sorting, hashing, formatting) and the readers live alongside the
 * wire-format constants they depend on. All readers are bounds-checked and
 * throw {@link Ja4ParseError} on truncation.
 */

import { Ja4ParseError } from "./ja4-errors.js";

/** GREASE values per RFC 8701 — these are reserved and must be ignored. */
export const GREASE_VALUES: ReadonlySet<number> = new Set([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/** TLS extension type numbers we special-case when parsing. */
export const EXT_SNI = 0x0000;
export const EXT_SUPPORTED_GROUPS = 0x000a;
export const EXT_EC_POINT_FORMATS = 0x000b;
export const EXT_ALPN = 0x0010;
export const EXT_SUPPORTED_VERSIONS = 0x002b;

/** TLS protocol-version codes → human-readable version string. */
export const TLS_VERSIONS: ReadonlyMap<number, string> = new Map<number, string>([
    [0x0304, "13"],
    [0x0303, "12"],
    [0x0302, "11"],
    [0x0301, "10"],
    [0x0300, "09"],
]);

/** Read a big-endian uint16 at `offset` in `buf` (unchecked — caller bounds). */
export function uint16(buf: Uint8Array, offset: number): number {
    const hi = buf[offset];
    const lo = buf[offset + 1];
    if (hi === undefined || lo === undefined) {
        throw new Ja4ParseError(`uint16 read out of bounds at offset ${offset}`);
    }
    return (hi << 8) | lo;
}

/** Read a 24-bit big-endian integer at `offset` in `buf`. */
export function uint24(buf: Uint8Array, offset: number): number {
    const hi = buf[offset];
    const mid = buf[offset + 1];
    const lo = buf[offset + 2];
    if (hi === undefined || mid === undefined || lo === undefined) {
        throw new Ja4ParseError(`uint24 read out of bounds at offset ${offset}`);
    }
    return (hi << 16) | (mid << 8) | lo;
}

/** Format a number as a 4-char lowercase hex string (`0x1a2b` → `"1a2b"`). */
export function hex4(value: number): string {
    return value.toString(16).padStart(4, "0");
}

/** Human-readable version string for a TLS `client_version` code. */
export function tlsVersionLabel(versionCode: number): string {
    return TLS_VERSIONS.get(versionCode) ?? versionCode.toString(16).padStart(2, "0");
}

/**
 * Read the non-GREASE supported_groups(10) list that starts at `pos`.
 * `pos` points at the 2-byte list length. Throws {@link Ja4ParseError} on
 * truncation.
 */
export function readSupportedGroups(clientHello: Uint8Array, pos: number): number[] {
    const listLen = uint16(clientHello, pos);
    const groups: number[] = [];
    for (let i = 0; i + 1 < listLen; i += 2) {
        const group = uint16(clientHello, pos + 2 + i);
        if (!GREASE_VALUES.has(group)) {
            groups.push(group);
        }
    }
    return groups;
}

/**
 * Read the ec_point_formats(11) list that starts at `pos`. `pos` points at the
 * 1-byte list length. Throws {@link Ja4ParseError} on truncation.
 */
export function readEcPointFormats(clientHello: Uint8Array, pos: number): number[] {
    const listLen = clientHello[pos];
    if (listLen === undefined) {
        throw new Ja4ParseError("ClientHello truncated at ec_point_formats length");
    }
    const formats: number[] = [];
    for (let i = 0; i < listLen; i++) {
        const fmt = clientHello[pos + 1 + i];
        if (fmt === undefined) {
            throw new Ja4ParseError("ClientHello truncated in ec_point_formats list");
        }
        formats.push(fmt);
    }
    return formats;
}

/**
 * Read the ALPN protocol list that starts at `pos`. `pos` points at the 2-byte
 * list length. Returns the comma-joined protocol string. Throws
 * {@link Ja4ParseError} on truncation.
 */
export function readAlpnProtocols(clientHello: Uint8Array, pos: number): string {
    const listLen = uint16(clientHello, pos);
    let cursor = pos + 2;
    const protocols: string[] = [];
    const listEnd = cursor + listLen;
    while (cursor < listEnd) {
        const protoLen = clientHello[cursor];
        if (protoLen === undefined) {
            throw new Ja4ParseError("ClientHello truncated at ALPN protocol length");
        }
        cursor += 1;
        protocols.push(new TextDecoder().decode(clientHello.subarray(cursor, cursor + protoLen)));
        cursor += protoLen;
    }
    return protocols.join(",");
}

