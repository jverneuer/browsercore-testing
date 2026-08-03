/**
 * JA4H — the HTTP-layer sibling of JA4 (docs/TEST-SUITE.md, Category 4).
 *
 * JA4H fingerprints an HTTP request from its method, version, header order,
 * cookies, and Accept-Language prefix. It is the HTTP analogue computed by the
 * reference provider to fingerprint a captured request. Independent of the TLS
 * ClientHello parsing in `ja4.ts`.
 *
 * Reference: https://github.com/FoxIO-LLC/JA4
 */

import { sha256First12 } from "./ja4.js";

/** The four computed JA4H parts. */
export interface Ja4hFingerprint {
    readonly a: string;
    readonly b: string;
    readonly c: string;
    readonly d: string;
    /** Canonical `JA4H_a_JA4H_b_JA4H_c_JA4H_d` tag. */
    readonly tag: string;
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
