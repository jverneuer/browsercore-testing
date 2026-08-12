/**
 * Live-server fetch test — TLS handshake + HTTP/1.1 round-trip against a real
 * public server.
 *
 * This is the permanent regression guard that proves the @browsercore stack
 * works end-to-end over the real internet: TCP connect → connectTls →
 * application data write (HTTP request) → application data read (HTTP response
 * decryption).
 *
 * Gated behind RUN_LIVE_TESTS=1 so CI (which may have no network) stays green.
 * Without the env var the suite is skipped entirely.
 *
 * Target: example.com:443 — a stable, always-available server with a valid TLS
 * certificate and a simple HTTP/1.1 response.
 */

import { describe, it, expect } from "vitest";
import { EventEmitter } from "node:events";
import { connect as netConnect, type Socket as NodeSocket } from "node:net";
import { connectTls } from "@browsercore/tls";
import { TLS_1_3 } from "@browsercore/tls";
import type { ClientHelloConfig, TlsConnection } from "@browsercore/tls";
import type { EventProvider } from "@browsercore/contracts";
import type { Transport, TransportState } from "@browsercore/transport";
import { nodeCryptoProvider as crypto } from "../../src/reference/node-crypto-provider.js";

const RUN_LIVE_TESTS = process.env.RUN_LIVE_TESTS === "1";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/**
 * Minimal Node-backed EventProvider adapter.
 *
 * @browsercore/tls requires an injected EventProvider via Platform composition.
 * This adapter wraps node:events.EventEmitter to satisfy the contract.
 */
class NodeEventProvider implements EventProvider {
    private readonly emitter = new EventEmitter();

    on(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.on(event, listener);
    }

    once(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.once(event, listener);
    }

    off(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.off(event, listener);
    }

    removeListener(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.removeListener(event, listener);
    }

    emit(event: string, ...args: unknown[]): boolean {
        return this.emitter.emit(event, ...args);
    }

    listenerCount(event: string): number {
        return this.emitter.listenerCount(event);
    }

    removeAllListeners(event?: string): void {
        this.emitter.removeAllListeners(event);
    }
}

/**
 * A Transport that wraps an already-connected TCP socket.
 *
 * Mirrors the TcpClientTransport from traffic-gate.test.ts — minimal
 * implementation of the @browsercore/transport interface backed by node:net.
 * The socket MUST be already connected before it is wrapped, so the TLS
 * handshake does not race with the TCP three-way handshake.
 */
class TcpClientTransport extends EventEmitter implements Transport {
    readonly id = "tcp-client";
    state: TransportState = { state: "open" };
    private socket: NodeSocket;
    private readQueue: Uint8Array[] = [];
    private waiters: Array<{
        resolve: (data: Uint8Array) => void;
        reject: (err: Error) => void;
    }> = [];

    constructor(socket: NodeSocket) {
        super();
        this.socket = socket;
        this.socket.on("data", (chunk: Buffer) => {
            const data = new Uint8Array(chunk);
            const waiter = this.waiters.shift();
            if (waiter) {
                waiter.resolve(data);
            } else {
                this.readQueue.push(data);
            }
        });
        this.socket.on("error", (err: Error) => {
            this.state = { state: "closed", reason: { kind: "error", error: err } };
            // Reject all pending read waiters so the TLS read loop unblocks.
            const pending = this.waiters;
            this.waiters = [];
            for (const w of pending) {
                w.reject(err);
            }
        });
        this.socket.on("close", () => {
            this.state = { state: "closed", reason: { kind: "remote_close" } };
            // Reject all pending read waiters so the TLS read loop unblocks.
            const pending = this.waiters;
            this.waiters = [];
            for (const w of pending) {
                w.reject(new Error("socket closed"));
            }
        });
    }

    async read(): Promise<Uint8Array> {
        const queued = this.readQueue.shift();
        if (queued !== undefined) return queued;
        return new Promise((resolve, reject) => {
            this.waiters.push({ resolve, reject });
        });
    }

    async write(data: Uint8Array): Promise<void> {
        this.socket.write(data);
    }

    async close(): Promise<void> {
        this.socket.destroy();
        this.state = { state: "closed", reason: { kind: "client_close" } };
    }
}

/**
 * Open a real TCP connection and wait for it to be fully established before
 * returning the connected socket. This ensures the TLS handshake does not start
 * until the TCP layer is ready.
 */
function openTcp(host: string, port: number, timeoutMs: number): Promise<NodeSocket> {
    return new Promise((resolve, reject) => {
        const socket = netConnect({ host, port });
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error(`TCP connect to ${host}:${port} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        socket.once("connect", () => {
            clearTimeout(timer);
            resolve(socket);
        });
        socket.once("error", (err: Error) => {
            clearTimeout(timer);
            reject(err);
        });
    });
}

/**
 * Minimal TLS 1.3 ClientHello profile for example.com.
 *
 * No ALPN is advertised — the server defaults to HTTP/1.1, which is what the
 * test sends.
 */
const PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 13, 43, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
    grease: false,
};

/**
 * Build a minimal HTTP/1.1 GET request. `Connection: close` tells the server
 * to close the connection after sending the full response.
 */
function httpRequest(host: string, path: string): Uint8Array {
    return encoder.encode(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`,
    );
}

/**
 * Read all decrypted application data until the server closes the connection.
 *
 * With `Connection: close`, the server sends the full response followed by a
 * TLS close_notify alert. This loop accumulates every APPLICATION_DATA record
 * and stops when read() throws (state transitions to "closed").
 */
async function readAll(conn: TlsConnection): Promise<string> {
    const chunks: Uint8Array[] = [];
    for (;;) {
        try {
            const data = await conn.read();
            chunks.push(data.payload);
        } catch {
            break;
        }
        const total = chunks.reduce((sum, c) => sum + c.length, 0);
        if (total > 1_048_576) break;
    }

    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
    }
    return decoder.decode(merged);
}

(RUN_LIVE_TESTS ? describe : describe.skip)("live fetch over @browsercore TLS", () => {
    it("completes TLS handshake and HTTP round-trip against example.com", async () => {
        // Establish the TCP connection first — the TLS handshake must not race
        // with the TCP three-way handshake.
        const socket = await openTcp("example.com", 443, 15_000);
        const transport = new TcpClientTransport(socket);
        const events = new NodeEventProvider();

        try {
            const conn = await connectTls({
                transport,
                crypto,
                events,
                serverName: "example.com",
                profile: PROFILE,
                onDebug: (msg: string) => console.error(`[tls-debug] ${msg}`),
            });

            // Handshake completed — connection is open for application data.
            expect(conn.state.state).toBe("open");

            // Send a real HTTP/1.1 GET request over the encrypted channel.
            await conn.write(httpRequest("example.com", "/"));

            // Read the decrypted HTTP response.
            const response = await readAll(conn);

            // The response is a full HTTP/1.1 message: status line + headers + body.
            expect(response).toContain("HTTP/1.1");
            expect(response.length).toBeGreaterThan(0);

            await conn.close();
        } finally {
            await transport.close();
        }
    }, 30_000);
});
