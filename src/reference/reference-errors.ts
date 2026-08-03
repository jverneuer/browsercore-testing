/**
 * Typed errors for the reference provider (docs/TEST-SUITE.md, Cat 3/4/14).
 *
 * Mirrors the transport pattern: errors carry a `kind` discriminator so callers
 * can match on type instead of parsing message text. `ReferenceError` is the
 * base failure for capture / fingerprint; `DumpParseError` covers the
 * curl-impersonate dump-format failures specifically.
 */

import { TestingError } from "../errors.js";

/**
 * Raised when a reference provider cannot capture or fingerprint a profile.
 *
 * Extends {@link TestingError} (the package-wide base) so it inherits the
 * `"TestingError"` discriminator; callers can `instanceof ReferenceError` for
 * the narrower match.
 */
export class ReferenceError extends TestingError {
    constructor(message: string, options?: { cause?: Error }) {
        super(message, options);
        this.name = "ReferenceError";
    }
}

/**
 * Raised when curl-impersonate `--dump-traffic` output cannot be parsed.
 *
 * Discriminated by {@link dumpKind}: `"no_hex"` (no hex bytes after the
 * marker) or `"odd_length"` (an odd number of hex digits cannot form whole
 * bytes).
 */
export class DumpParseError extends ReferenceError {
    public readonly dumpKind: DumpParseKind;
    public readonly hexLength: number;

    constructor(dumpKind: DumpParseKind, hexLength: number) {
        const message =
            dumpKind === "no_hex"
                ? "curl-impersonate dump produced no hex bytes"
                : `curl-impersonate dump produced odd-length hex (${hexLength})`;
        super(message);
        this.name = "DumpParseError";
        this.dumpKind = dumpKind;
        this.hexLength = hexLength;
    }
}

/** Why a dump could not be parsed. */
export type DumpParseKind = "no_hex" | "odd_length";
