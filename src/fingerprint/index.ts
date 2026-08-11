/** Barrel for fingerprint computation (JA3 / JA4 / JA4H). */
export { computeJa3, parseClientHello, Ja3ParseError } from "./ja3.js";
export type { Ja3Segments } from "./ja3.js";
export { computeJa4, computeJa4Fingerprint, Ja4ParseError } from "./ja4.js";
export type { Ja4ClientHello, Ja4Fingerprint } from "./ja4.js";
export { computeJa4h } from "./ja4h.js";
export type { Ja4hFingerprint, Ja4hRequest } from "./ja4h.js";

// Akamai HTTP/2 fingerprint string builder (Cat 4).
export { buildAkamaiFingerprint, H2_SETTINGS } from "./akamai-http2.js";
export type {
    AkamaiFingerprintInput,
    H2PseudoHeader,
    H2Setting,
} from "./akamai-http2.js";
