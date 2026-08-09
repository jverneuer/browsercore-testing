/**
 * Bug 6 regression test: AES-128-GCM record decryption during TLS 1.3 handshake.
 *
 * Drives the @browsercore/tls client against a real TLS 1.3 server (TrafficServer)
 * that performs a genuine handshake then sends an encrypted HTTP response.
 * The client must decrypt the ENTIRE server flight — if AEAD key derivation,
 * nonce construction, or record parsing is wrong, this test fails.
 *
 * This is the deterministic, network-free reproduction for Bug 6.
 */

import { describe, expect, it } from "vitest";
import { EventEmitter } from "node:events";
import { connect as netConnect, type Socket } from "node:net";
import { connectTls } from "@browsercore/tls";
import { nodeCryptoProvider as crypto } from "../../src/reference/node-crypto-provider.js";
import type { EventProvider } from "@browsercore/contracts";
import { TrafficServer } from "../../src/e2e/traffic-server.js";
import type { Transport, TransportState } from "@browsercore/transport";
import type { ClientHelloConfig } from "@browsercore/tls";
import { TLS_1_3 } from "@browsercore/tls";

/**
 * Minimal Node-backed EventProvider adapter.
 *
 * @browsercore/tls 0.4.2 requires an injected `EventProvider` via Platform
 * composition. This repo provides a thin adapter over node:events.EventEmitter
 * to satisfy the contract without depending on browsersmith.
 */
class NodeEventProvider implements EventProvider {
    private readonly emitter = new EventEmitter();

    on(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.on(event, listener as (...args: unknown[]) => void);
    }

    once(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.once(event, listener as (...args: unknown[]) => void);
    }

    off(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.off(event, listener as (...args: unknown[]) => void);
    }

    removeListener(event: string, listener: (...args: unknown[]) => void): void {
        this.emitter.removeListener(event, listener as (...args: unknown[]) => void);
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
 * Minimal TLS 1.3 profile for e2e traffic tests.
 * GREASE disabled: Node.js tls rejects unknown GREASE key-share groups,
 * while real servers ignore them. We test decryption, not GREASE handling.
 */
const TRAFFIC_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    // Minimal extension set for testing decryption: only extensions OpenSSL
    // accepts in a TLS 1.3 ClientHello. No PSK (must be last + needs binders),
    // no compress_certificate, no TLS 1.2 legacy extensions that trigger
    // ERR_SSL_BAD_EXTENSION.
    extensionOrder: [0, 10, 11, 13, 16, 43, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "localhost",
    grease: false,
    alpnProtocols: ["h2", "http/1.1"],
};

/**
 * A Transport that connects to the traffic server over real TCP.
 * Minimal implementation of the @browsercore/transport interface.
 */
class TcpClientTransport extends EventEmitter implements Transport {
    readonly id = "tcp-client";
    state: TransportState = { state: "connecting" };
    private socket: Socket;
    private readQueue: Uint8Array[] = [];
    private waiters: Array<(data: Uint8Array) => void> = [];

    constructor(host: string, port: number) {
        super();
        this.socket = netConnect({ host, port });
        this.socket.on("data", (chunk: Buffer) => {
            const data = new Uint8Array(chunk);
            const waiter = this.waiters.shift();
            if (waiter) { waiter(data); } else { this.readQueue.push(data); }
        });
        this.socket.on("connect", () => { this.state = { state: "open" }; });
        this.socket.on("error", (err: Error) => {
            this.state = { state: "closed", reason: { kind: "error", error: err } };
        });
        this.socket.on("close", () => {
            this.state = { state: "closed", reason: { kind: "remote_close" } };
        });
    }

    async read(): Promise<Uint8Array> {
        const queued = this.readQueue.shift();
        if (queued !== undefined) return queued;
        return new Promise((resolve) => { this.waiters.push(resolve); });
    }

    async write(data: Uint8Array): Promise<void> {
        this.socket.write(data);
    }

    async close(): Promise<void> {
        this.socket.destroy();
        this.state = { state: "closed", reason: { kind: "client_close" } };
    }
}

describe("Bug 6: AES-128-GCM record decryption (e2e traffic)", () => {
    it("completes handshake and decrypts server response", async () => {
        const server = await TrafficServer.start();
        const handshakeResult = server.waitForHandshake(5000);
        const events = new NodeEventProvider();

        const transport = new TcpClientTransport(server.host, server.port);
        const conn = await connectTls({
            transport,
            crypto,
            events,
            serverName: "localhost",
            profile: TRAFFIC_PROFILE,
            // Self-signed cert: skip chain verification, hostname still validates
            trustAnchors: [],
        });

        // Handshake completed
        const handshake = await handshakeResult;
        expect(handshake.protocolVersion).toBe("TLSv1.3");
        expect(handshake.cipherSuite).toContain("AES");

        // Connection is open — decryption of handshake flight succeeded
        expect(conn.state.state).toBe("open");

        // Read the encrypted application data the server sent
        const response = await conn.read();
        const body = new TextDecoder().decode(response.payload);
        expect(body).toContain("TRAFFIC_GATE_OK_BUG6");

        await conn.close();
        await server.stop();
    }, 10000);

    it("negotiates ALPN and decrypts response", async () => {
        const server = await TrafficServer.start();
        const handshakeResult = server.waitForHandshake(5000);
        const events = new NodeEventProvider();

        const transport = new TcpClientTransport(server.host, server.port);
        const conn = await connectTls({
            transport,
            crypto,
            events,
            serverName: "localhost",
            profile: TRAFFIC_PROFILE,
            trustAnchors: [],
        });

        const handshake = await handshakeResult;
        // ALPN should negotiate http/1.1 (the only protocol the server offers that the client supports)
        expect(["http/1.1", "h2"]).toContain(handshake.alpnProtocol);

        const response = await conn.read();
        const body = new TextDecoder().decode(response.payload);
        expect(body).toContain("TRAFFIC_GATE_OK_BUG6");

        await conn.close();
        await server.stop();
    }, 10000);
});
