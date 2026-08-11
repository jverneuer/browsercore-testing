/**
 * Akamai HTTP/2 fingerprint (docs/TEST-SUITE.md, Category 4).
 *
 * The "Akamai fingerprint" (a.k.a. the HTTP/2 fingerprint popularized by
 * Akamai's bot-detection research) serializes a connection's HTTP/2
 * signature into a single pipe-delimited string:
 *
 *   SETTINGS|WINDOW_UPDATE|PRIORITY_FRAMES|PSEUDO_HEADER_ORDER
 *
 * where:
 *   SETTINGS             = `id:value;id:value;…` — each SETTINGS parameter in
 *                          the order the client emitted it (RFC 9113 §6.5.2).
 *   WINDOW_UPDATE        = the single connection-level WINDOW_UPDATE increment
 *                          the client sent in its preface.
 *   PRIORITY_FRAMES      = count of PRIORITY frames in the connection preface.
 *   PSEUDO_HEADER_ORDER  = comma-joined single-letter codes for the pseudo
 *                          header order on the first request
 *                          (`:method`→m, `:authority`→a, `:scheme`→s,
 *                          `:path`→p).
 *
 * Example Chrome 131 string:
 *   `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
 *
 * This is an HTTP-layer fingerprint — independent of the TLS ClientHello
 * parsing in {@link ./ja4.ts}.
 */

/** HTTP/2 SETTINGS parameter identifiers (RFC 9113 §6.5.2). */
export const H2_SETTINGS = {
    /** SETTINGS_HEADER_TABLE_SIZE. */
    HEADER_TABLE_SIZE: 1,
    /** SETTINGS_ENABLE_PUSH. */
    ENABLE_PUSH: 2,
    /** SETTINGS_MAX_CONCURRENT_STREAMS. */
    MAX_CONCURRENT_STREAMS: 3,
    /** SETTINGS_INITIAL_WINDOW_SIZE. */
    INITIAL_WINDOW_SIZE: 4,
    /** SETTINGS_MAX_FRAME_SIZE. */
    MAX_FRAME_SIZE: 5,
    /** SETTINGS_MAX_HEADER_LIST_SIZE. */
    MAX_HEADER_LIST_SIZE: 6,
    /** SETTINGS_ENABLE_CONNECT_PROTOCOL. */
    ENABLE_CONNECT_PROTOCOL: 8,
} as const;

/** A single HTTP/2 SETTINGS parameter, in the wire order it was sent. */
export interface H2Setting {
    /** IANA SETTINGS identifier (e.g. 1 for HEADER_TABLE_SIZE). */
    readonly id: number;
    /** The parameter value as a 32-bit unsigned integer. */
    readonly value: number;
}

/** The four HTTP/2 request pseudo-headers (RFC 9113 §8.1). */
export type H2PseudoHeader = ":method" | ":authority" | ":scheme" | ":path";

/**
 * HTTP/2 connection parameters needed to build the Akamai fingerprint.
 *
 * `settings` is in the order the client emitted them — Akamai fingerprinting
 * is order-sensitive, so callers must preserve wire order. `pseudoHeaderOrder`
 * is the order of pseudo-headers on the first (HEADERS) request.
 */
export interface AkamaiFingerprintInput {
    /** SETTINGS parameters in wire order. */
    readonly settings: readonly H2Setting[];
    /** Connection-level WINDOW_UPDATE increment sent in the preface. */
    readonly windowUpdateIncrement: number;
    /** Number of PRIORITY frames in the connection preface. */
    readonly priorityFrameCount: number;
    /** Pseudo-header order of the first request. */
    readonly pseudoHeaderOrder: readonly H2PseudoHeader[];
}

/** Single-letter Akamai code for a pseudo-header. */
function pseudoHeaderCode(header: H2PseudoHeader): string {
    switch (header) {
        case ":method":
            return "m";
        case ":authority":
            return "a";
        case ":scheme":
            return "s";
        case ":path":
            return "p";
    }
}

/**
 * Build the Akamai HTTP/2 fingerprint string from connection parameters.
 *
 * The result is `SETTINGS|WINDOW_UPDATE|PRIORITY_FRAMES|PSEUDO_HEADER_ORDER`.
 * An empty SETTINGS list serializes to an empty segment (leading `|`).
 */
export function buildAkamaiFingerprint(input: AkamaiFingerprintInput): string {
    const settingsPart = input.settings
        .map((s) => `${s.id}:${s.value}`)
        .join(";");
    const pseudoPart = input.pseudoHeaderOrder.map(pseudoHeaderCode).join(",");
    return [
        settingsPart,
        String(input.windowUpdateIncrement),
        String(input.priorityFrameCount),
        pseudoPart,
    ].join("|");
}
