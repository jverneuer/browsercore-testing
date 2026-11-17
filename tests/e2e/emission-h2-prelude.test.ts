/**
 * REAL HTTP/2 emission test — the wire prelude of the REAL connection stack.
 *
 * Today's lesson (0.2.9): goldens that only self-compare catch nothing. This
 * file drives the REAL `@browsercore/http2` 0.2.11 connection over a fake
 * duplex transport configured from the REAL chrome-140 profile
 * (`@browsercore/profiles` 0.2.4), exactly as `@browsercore/fetch` wires it,
 * and asserts the emitted bytes against ORACLE ground truth — not against our
 * own output.
 *
 * Oracles (every asserted constant cites its source):
 *   - captures/chrome-131/oracle_capture.reference.json `http2` section:
 *     SETTINGS sent_frames[0] = 4 entries in order 1:65536; 2:0; 4:6291456;
 *     6:262144 (24-byte payload), WINDOW_UPDATE increment 15663105, request
 *     HEADERS on stream 1 with flags EndStream(0x1) | EndHeaders(0x4) |
 *     Priority(0x20) = 0x25 and priority {weight 256 (wire 0xff), depends_on
 *     0, exclusive 1}, pseudo-header order m,a,s,p, and no `host` field.
 *     Chrome's h2 prelude is identical from 131 through 140; the chrome-140
 *     profile in @browsercore/profiles 0.2.4 declares the same values.
 *   - captures/chrome-140/http2/settings.bin — the regenerated REAL golden
 *     (0.2.9), byte-identical to the chrome-131 capture.
 *
 * The `host`-over-h2 strip lives in @browsercore/fetch's dispatch layer; the
 * wire contract it produces (authority carried by :authority, no `host`
 * header field — RFC 9113 §8.3.6) is asserted here on the emitted frame,
 * which is where the wire is observable.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { connectHttp2, FrameType, HpackDecoder, Http2Settings } from "@browsercore/http2";
import type { HeaderField, Http2Connection, Http2SettingsMap, Http2StreamId } from "@browsercore/http2";
import { getProfile } from "@browsercore/profiles";
import type { BrowserProfile, ProfileId } from "@browsercore/profiles";
import { loadGolden } from "../../src/golden/golden.js";
import { nodeCryptoProvider } from "../../src/reference/node-crypto-provider.js";
import { CaptureTransport, captureEventProvider, toHex } from "./emission-fakes.js";
import type { CaptureId } from "../../src/types.js";

// --- oracle ground truth (captures/chrome-131/oracle_capture.reference.json) -

/** Published Chrome Akamai h2 fingerprint — the SETTINGS segment is order-sensitive. */
const ORACLE_AKAMAI_SETTINGS = "1:65536;2:0;4:6291456;6:262144";
/** Published connection-level WINDOW_UPDATE increment (akamai segment 2). */
const ORACLE_WINDOW_UPDATE_INCREMENT = 15663105;
/** Published pseudo-header order segment: m,a,s,p. */
const ORACLE_PSEUDO_ORDER = [":method", ":authority", ":scheme", ":path"] as const;
/** Wire bytes of the oracle's HEADERS priority block (excl bit + dep 0 + weight 0xff). */
const ORACLE_PRIORITY_BLOCK = Uint8Array.from([0x80, 0x00, 0x00, 0x00, 0xff]);

/** RFC 7540 §3.5 client connection preface. */
const CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// --- chrome-140 → Http2Options (mirrors @browsercore/fetch profileHttp2Config)

/** Translate the profile's named settings to the numeric SETTINGS map (RFC 9113 §6.5.1). */
function profileSettingsMap(profile: BrowserProfile): Http2SettingsMap {
    const named = profile.http2.settings;
    const wire: Http2SettingsMap = {};
    if (named.headerTableSize !== undefined) {
        wire[Http2Settings.HEADER_TABLE_SIZE] = named.headerTableSize;
    }
    if (named.enablePush !== undefined) {
        wire[Http2Settings.ENABLE_PUSH] = named.enablePush ? 1 : 0;
    }
    if (named.maxConcurrentStreams !== undefined) {
        wire[Http2Settings.MAX_CONCURRENT_STREAMS] = named.maxConcurrentStreams;
    }
    if (named.initialWindowSize !== undefined) {
        wire[Http2Settings.INITIAL_WINDOW_SIZE] = named.initialWindowSize;
    }
    if (named.maxFrameSize !== undefined) {
        wire[Http2Settings.MAX_FRAME_SIZE] = named.maxFrameSize;
    }
    if (named.maxHeaderListSize !== undefined) {
        wire[Http2Settings.MAX_HEADER_LIST_SIZE] = named.maxHeaderListSize;
    }
    return wire;
}

/**
 * The HEADERS priority the oracle observes on every Chrome request: exclusive
 * dependency on stream 0 with wire weight 0xff (logical 256 — the profile's
 * `http2.weight`). `initialPriority` is the @browsercore/http2 0.2.11 option
 * that sets the PRIORITY flag (0x20) + 5-byte block on request HEADERS.
 */
const CHROME_REQUEST_PRIORITY = {
    exclusive: true,
    // Root-stream dependency 0 — the branded id type (standards §14).
    streamDependency: 0 as Http2StreamId,
    weight: 0xff,
} as const;

// --- helpers ----------------------------------------------------------------

/** One captured client write, parsed as an HTTP/2 frame. */
interface CapturedFrame {
    readonly type: number;
    readonly flags: number;
    readonly streamId: number;
    readonly payload: Uint8Array;
    readonly raw: Uint8Array;
}

function parseCapturedFrame(raw: Uint8Array): CapturedFrame {
    const length = (raw[0]! << 16) | (raw[1]! << 8) | raw[2]!;
    return {
        type: raw[3]!,
        flags: raw[4]!,
        streamId: ((raw[5]! << 24) | (raw[6]! << 16) | (raw[7]! << 8) | raw[8]!) >>> 0,
        payload: raw.subarray(9, 9 + length),
        raw,
    };
}

/** All captured writes that are frames (i.e. everything after the preface). */
function capturedFrames(transport: CaptureTransport): CapturedFrame[] {
    return transport.writes.slice(1).map(parseCapturedFrame);
}

/** Render a SETTINGS payload as the Akamai order-sensitive segment string. */
function akamaiSettingsSegment(payload: Uint8Array): string {
    const entries: string[] = [];
    for (let i = 0; i + 5 < payload.length; i += 6) {
        const id = (payload[i]! << 8) | payload[i + 1]!;
        const value =
            (payload[i + 2]! << 24) | (payload[i + 3]! << 16) | (payload[i + 4]! << 8) | payload[i + 5]!;
        entries.push(`${id}:${value >>> 0}`);
    }
    return entries.join(";");
}

/** Wait until the transport has captured at least `count` writes. */
async function waitForWrites(transport: CaptureTransport, count: number): Promise<void> {
    await vi.waitFor(() => {
        expect(transport.writes.length).toBeGreaterThanOrEqual(count);
    });
}

// ----------------------------------------------------------------------------

describe("REAL h2 emission — chrome-140 prelude vs oracle", () => {
    const SERVER_NAME = "tls.peet.ws";
    const profile = getProfile("chrome-140" as ProfileId);

    let transport: CaptureTransport;
    let conn: Http2Connection;

    /** Server-side half of the settings exchange: empty SETTINGS + ACK of ours. */
    function feedServerSettingsExchange(): void {
        transport.feed(
            Uint8Array.from([
                // SETTINGS (empty): server's own preface frame.
                0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                // SETTINGS ACK for our preface SETTINGS (RFC 9113 §6.5.3).
                0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
            ]),
        );
    }

    beforeAll(async () => {
        transport = new CaptureTransport();
        conn = await connectHttp2({
            transport,
            events: captureEventProvider(),
            crypto: nodeCryptoProvider,
            // Wired exactly as @browsercore/fetch's establishConnection h2
            // branch wires it from the profile (dispatch.js, fetch 0.2.18).
            // The profile's optional h2 fields arrive as `T | undefined`;
            // exactOptionalPropertyTypes forbids writing `undefined` into
            // Http2Options' optional fields, so each is spread only when the
            // profile carries it.
            initialSettings: profileSettingsMap(profile),
            ...(profile.http2.settingsOrder !== undefined
                ? { settingsOrder: profile.http2.settingsOrder }
                : {}),
            ...(profile.http2.grease !== undefined ? { settingsGrease: profile.http2.grease } : {}),
            ...(profile.http2.connectionWindowUpdate !== undefined
                ? { connectionWindowUpdate: profile.http2.connectionWindowUpdate }
                : {}),
            ...(profile.http2.pseudoHeaderOrder !== undefined
                ? { pseudoHeaderOrder: profile.http2.pseudoHeaderOrder }
                : {}),
            // Plus the request-HEADERS priority (oracle flags 0x25 + 5-byte
            // block) carried by the profile's http2.weight (256 → wire 0xff).
            initialPriority: CHROME_REQUEST_PRIORITY,
        });
        feedServerSettingsExchange();
        // Fire a request (response is never fed; we assert the REQUEST bytes).
        void conn
            .request({
                method: "GET",
                scheme: "https",
                authority: SERVER_NAME,
                path: "/api/all",
                headers: new Map<string, string>([
                    // The header set @browsercore/fetch delivers to this layer
                    // after applying profile defaults: accept-encoding from
                    // http1.acceptEncoding, `priority` from http2DefaultHeaders
                    // (profiles 0.2.4), and NO `host` — over h2 the authority
                    // lives in :authority (RFC 9113 §8.3.6; fetch strips it).
                    ["user-agent", profile.http1.defaultHeaders["user-agent"] ?? ""],
                    ["accept", profile.http1.defaultHeaders["accept"] ?? ""],
                    ["accept-encoding", profile.http1.acceptEncoding],
                    ["priority", profile.http2.http2DefaultHeaders?.["priority"] ?? ""],
                ]),
                body: undefined,
            })
            .catch(() => undefined);
        // preface + SETTINGS + WINDOW_UPDATE (+ maybe SETTINGS ACK) + HEADERS.
        await waitForWrites(transport, 4);
    });

    afterAll(async () => {
        await conn.close().catch(() => undefined);
    });

    it("opens with the RFC 7540 §3.5 client connection preface", () => {
        expect(new TextDecoder().decode(transport.writes[0]!)).toBe(CLIENT_PREFACE);
    });

    it("emits the oracle's SETTINGS frame byte-for-byte (4 entries, 24-byte payload, in order)", () => {
        const frames = capturedFrames(transport);
        const settings = frames.find(
            (frame) => frame.type === FrameType.SETTINGS && (frame.flags & 0x1) === 0,
        );
        expect(settings).toBeDefined();

        // The regenerated REAL golden (oracle-derived, 0.2.9) — byte-for-byte.
        const golden = loadGolden("chrome-140/http2/settings" as CaptureId);
        expect(toHex(settings!.raw)).toBe(toHex(golden.bytes));

        // And the order-sensitive Akamai segment matches the oracle string
        // (chrome-131 oracle: "1:65536;2:0;4:6291456;6:262144").
        expect(settings!.payload.length).toBe(24);
        expect(akamaiSettingsSegment(settings!.payload)).toBe(ORACLE_AKAMAI_SETTINGS);
    });

    it("emits the oracle's connection WINDOW_UPDATE (15663105) on stream 0", () => {
        const frames = capturedFrames(transport);
        const windowUpdate = frames.find((frame) => frame.type === FrameType.WINDOW_UPDATE);
        expect(windowUpdate).toBeDefined();
        expect(windowUpdate!.streamId).toBe(0);
        const increment =
            (windowUpdate!.payload[0]! << 24) |
            (windowUpdate!.payload[1]! << 16) |
            (windowUpdate!.payload[2]! << 8) |
            windowUpdate!.payload[3]!;
        expect(increment >>> 0).toBe(ORACLE_WINDOW_UPDATE_INCREMENT);
    });

    it("sends request HEADERS on stream 1 with flags 0x25 + the 5-byte priority block", () => {
        const headers = capturedFrames(transport).find((frame) => frame.type === FrameType.HEADERS);
        expect(headers).toBeDefined();

        // Oracle sent_frames[2]: stream 1, flags EndStream|EndHeaders|Priority.
        expect(headers!.streamId).toBe(1);
        expect(headers!.flags).toBe(0x25);

        // PRIORITY flag ⇒ payload opens with the RFC 7540 §6.2 block:
        // exclusive-dependency bit + 31-bit stream dependency 0, weight 0xff
        // (logical 256). Oracle: {weight: 256, depends_on: 0, exclusive: 1}.
        expect(headers!.payload.subarray(0, 5)).toEqual(ORACLE_PRIORITY_BLOCK);
    });

    it("serializes pseudo-headers in the oracle's order m,a,s,p with no `host` field", () => {
        const headers = capturedFrames(transport).find((frame) => frame.type === FrameType.HEADERS);
        expect(headers).toBeDefined();

        // Decode the HPACK fragment (after the 5-byte priority block) with the
        // REAL decoder — the wire header order is preserved in the field list.
        const decoder = new HpackDecoder();
        const block: readonly HeaderField[] = decoder.decode(headers!.payload.subarray(5));
        const names = block.map((field) => field.name);

        // Oracle pseudo-header order: :method,:authority,:scheme,:path.
        expect(names.slice(0, 4)).toEqual([...ORACLE_PSEUDO_ORDER]);

        // RFC 9113 §8.3.6 / fetch 0.2.18: authority is carried by :authority —
        // a `host` field on an h2 request is a live-confirmed WAF trigger.
        expect(names).not.toContain("host");
        expect(names).not.toContain(":host");

        // The profile-driven h2 default header reaches the wire (chrome-140
        // http2DefaultHeaders: priority "u=0, i" — oracle header list).
        const priority = block.find((field) => field.name === "priority");
        expect(priority?.value).toBe("u=0, i");

        // And the profile-driven accept-encoding default (fetch 0.2.18) too.
        const acceptEncoding = block.find((field) => field.name === "accept-encoding");
        expect(acceptEncoding?.value).toBe(profile.http1.acceptEncoding);
    });
});
