/**
 * Shared types for the reference provider layer.
 *
 * Lives in its own module so the providers (`curl-provider.ts`,
 * `browser-provider.ts`), the dump helpers (`dump.ts`), and the facade
 * (`reference.ts`) all import from one place without forming an import cycle.
 */

import type { ProfileId } from "@browsercore/profiles";
import type { GoldenCapture } from "../types.js";

/** Which reference backend to use. Discriminated union — no bare string. */
export type ReferenceProviderKind =
    | { readonly kind: "curl-impersonate" }
    | { readonly kind: "real-browser" };

/** Observable TLS/HTTP fingerprint of a captured reference exchange. */
export interface Fingerprint {
    readonly ja3: string;
    readonly ja4: string;
    readonly alpn: readonly string[];
    readonly cipherSuite: string;
    readonly protocolVersion: string;
    readonly signatureAlgorithms: readonly string[];
    readonly ellipticCurves: readonly string[];
}

/** A source of truth for a browser profile's wire behavior. */
export interface ReferenceProvider {
    readonly kind: ReferenceProviderKind;
    capture(profile: ProfileId, url: string): Promise<GoldenCapture>;
    fingerprint(profile: ProfileId): Promise<Fingerprint>;
    availableProfiles(): ProfileId[];
}
