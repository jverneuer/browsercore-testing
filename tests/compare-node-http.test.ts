/**
 * Wire-format oracle tests: compare our @browsercore/http1 and @browsercore/http2
 * on-the-wire output against the layouts Node's own http/http2 stacks produce.
 *
 * These are equivalence tests for the SERIALIZED FORM only (RFC 7230 / RFC 7540),
 * using the deterministic oracle in `src/reference/node-reference.ts`. They assert
 * our bytes match what Node would emit/accept on the wire. Browser-fingerprint
 * divergence (TLS, HTTP/2 SETTINGS, default headers) is intentionally NOT tested
 * here — see `node-reference.ts` for the layering rule.
 */

import { describe, expect, it } from "vitest";
import { serializeRequest, parseResponse } from "@browsercore/http1";
import {
    serializeFrame,
    parseFrame,
    parseFrameHeader,
    FRAME_HEADER_LENGTH,
} from "@browsercore/http2";
import {
    FrameType,
    type Http2StreamId,
    type PingFrame,
    type SettingsFrame,
    type WindowUpdateFrame,
} from "@browsercore/http2";
import { nodeHttp } from "../src/reference/node-reference.js";

/** Brand a plain number as an Http2StreamId (load-bearing type, not bare number). */
function sid(n: number): Http2StreamId {
    return n as Http2StreamId;
}

/** Encode a string to ASCII bytes, matching the oracle's TextEncoder usage. */
function encode(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

describe("HTTP/1.1 request serialization vs node:http format", () => {
    it("GET with no headers serializes identically to node format", () => {
        const headers = new Map<string, string>();
        const req = {
            method: "GET" as const,
            url: "/index.html",
            headers,
            body: { kind: "empty" as const },
        };
        const ours = serializeRequest(req);
        const nodes = nodeHttp.serializeRequestLineAndHeaders("GET", "/index.html", headers);
        expect(ours).toEqual(nodes);
    });

    it("POST with headers: our header block matches node's header block", () => {
        const headers = new Map<string, string>([
            ["host", "example.com"],
            ["content-type", "text/plain"],
        ]);
        const body = encode("hi");
        const req = {
            method: "POST" as const,
            url: "/submit",
            headers,
            body: { kind: "bytes" as const, data: body },
        };

        const ours = serializeRequest(req);
        const text = new TextDecoder().decode(ours);

        // Request line + each header line, exactly as node:http emits them.
        expect(text.startsWith("POST /submit HTTP/1.1\r\n")).toBe(true);
        expect(text).toContain("host: example.com\r\n");
        expect(text).toContain("content-type: text/plain\r\n");

        // The request-line + headers portion is byte-identical to the oracle;
        // only the body bytes follow the blank line.
        const nodeHeaderBlock = nodeHttp.serializeRequestLineAndHeaders("POST", "/submit", headers);
        expect(ours.slice(0, nodeHeaderBlock.length)).toEqual(nodeHeaderBlock);
        expect(ours.slice(nodeHeaderBlock.length)).toEqual(body);
    });

    it("header names are lowercased like node:http does", () => {
        const headers = new Map<string, string>([["Content-Type", "text/plain"]]);
        const req = {
            method: "POST" as const,
            url: "/",
            headers,
            body: { kind: "empty" as const },
        };
        const text = new TextDecoder().decode(serializeRequest(req));
        expect(text).toContain("content-type: text/plain\r\n");
        expect(text).not.toContain("Content-Type:");
    });
});

describe("HTTP/1.1 response parsing", () => {
    it("parseResponse parses a status-line + headers + body like node would produce", () => {
        const raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        const buf = encode(raw);
        const { response, bytesConsumed } = parseResponse(buf);

        expect(response.statusCode).toBe(200);
        expect(response.statusText).toBe("OK");
        expect(response.headers.get("content-type")).toBe("text/plain");
        expect(response.headers.get("content-length")).toBe("5");
        expect(response.body).toEqual(encode("hello"));
        expect(bytesConsumed).toBe(buf.length);
    });

    it("parseResponse handles multiple headers and preserves order", () => {
        const raw =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Request-Id: abc123\r\nContent-Length: 2\r\n\r\nhi";
        const { response } = parseResponse(encode(raw));

        expect(response.headers.size).toBe(3);
        // Map preserves insertion order — assert the parsed sequence verbatim.
        expect([...response.headers.entries()]).toEqual([
            ["content-type", "text/plain"],
            ["x-request-id", "abc123"],
            ["content-length", "2"],
        ]);
        expect(response.body).toEqual(encode("hi"));
    });

    it("parseResponse on chunked-like body reads Content-Length body correctly", () => {
        // No transfer-encoding; a precise Content-Length delimits the body.
        const bodyText = "hello world";
        const raw = `HTTP/1.1 204 No Content\r\nContent-Length: ${bodyText.length}\r\n\r\n${bodyText}`;
        const buf = encode(raw);
        const { response, bytesConsumed } = parseResponse(buf);

        expect(response.statusCode).toBe(204);
        expect(response.body).toEqual(encode(bodyText));
        expect(bytesConsumed).toBe(buf.length);
    });
});

describe("HTTP/2 frame wire format vs node:http2", () => {
    it("serialized SETTINGS frame header has correct length/type/flags/streamId layout", () => {
        const frame: SettingsFrame = {
            type: FrameType.SETTINGS,
            flags: 0,
            streamId: sid(0),
            ack: false,
            settings: {},
        };
        const bytes = serializeFrame(frame);

        // RFC 7540 §4.1: 24-bit length | 8-bit type | 8-bit flags | 31-bit stream id.
        const length = (bytes[0]! << 16) | (bytes[1]! << 8) | bytes[2]!;
        expect(length).toBe(0);
        expect(bytes[3]).toBe(FrameType.SETTINGS);
        expect(bytes[3]).toBe(0x4);
        expect(bytes[4]).toBe(0);
        // Stream id is big-endian uint32 in bytes 5-8 (top bit reserved).
        const streamId = (bytes[5]! << 24) | (bytes[6]! << 16) | (bytes[7]! << 8) | bytes[8]!;
        expect(streamId).toBe(0);
    });

    it("parseFrameHeader round-trips serializeFrame for a PING frame", () => {
        const frame: PingFrame = {
            type: FrameType.PING,
            flags: 0,
            streamId: sid(0),
            ack: false,
            opaqueData: 0x0102030405060708n,
        };
        const bytes = serializeFrame(frame);
        const header = parseFrameHeader(bytes);

        expect(header.type).toBe(FrameType.PING);
        expect(header.type).toBe(0x6);
        expect(header.length).toBe(8);
        expect(header.flags).toBe(0);
        expect(header.streamId).toBe(0);
    });

    it("parseFrame then serializeFrame is identity for a WINDOW_UPDATE", () => {
        const frame: WindowUpdateFrame = {
            type: FrameType.WINDOW_UPDATE,
            flags: 0,
            streamId: sid(1),
            windowSizeIncrement: 65535,
        };
        const bytes = serializeFrame(frame);
        const parsed = parseFrame(bytes) as WindowUpdateFrame;

        expect(parsed.type).toBe(FrameType.WINDOW_UPDATE);
        expect(parsed.streamId).toBe(1);
        expect(parsed.windowSizeIncrement).toBe(65535);
        // Full structural equality against the original discriminated-union value.
        expect(parsed).toEqual(frame);
    });

    it("frame header is always 9 bytes (FRAME_HEADER_LENGTH)", () => {
        const frame: PingFrame = {
            type: FrameType.PING,
            flags: 0,
            streamId: sid(0),
            ack: false,
            opaqueData: 0n,
        };
        const bytes = serializeFrame(frame);

        expect(bytes.length).toBeGreaterThanOrEqual(FRAME_HEADER_LENGTH);
        // The first 9 bytes are the fixed header; re-parsing them recovers the
        // type and the payload length that accounts for the remaining bytes.
        const header = parseFrameHeader(bytes.slice(0, FRAME_HEADER_LENGTH));
        expect(header.type).toBe(FrameType.PING);
        expect(bytes.length).toBe(FRAME_HEADER_LENGTH + header.length);
    });
});

describe("HTTP/2 documented gaps (stubs — not yet implemented)", () => {
    it.todo(
        "HPACK encode matches node:http2 Http2Session outbound headers once @browsercore/http2 hpack is implemented",
    );
    it.todo(
        "full HTTP/2 connection SETTINGS exchange matches node:http2 once @browsercore/http2 connection is implemented",
    );
});
