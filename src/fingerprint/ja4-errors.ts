/**
 * Typed errors for JA4 / JA4H fingerprint parsing.
 *
 * Mirrors the transport pattern: a dedicated errors module so callers can
 * match on `kind` instead of parsing message text. Kept separate from
 * `ja4.ts` and `ja4h.ts` so neither fingerprint module owns the error type
 * the other depends on.
 */

/**
 * Reasons a ClientHello (JA4) or HTTP request (JA4H) cannot be parsed into a
 * fingerprint input.
 */
export class Ja4ParseError extends Error {
    public readonly kind = "Ja4ParseError" as const;
    constructor(message: string) {
        super(message);
        this.name = "Ja4ParseError";
    }
}
