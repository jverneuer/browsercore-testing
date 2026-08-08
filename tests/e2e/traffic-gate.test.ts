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
import { crypto } from "@browsercore/crypto";
import { connectTls } from "@browsercore/tls";
import { TrafficServer } from "../../src/e2e/traffic-server.js";
import type { Transport, TransportState } from "@browsercore/transport";
import type { ClientHelloConfig } from "@browsercore/tls";
import { TLS_1_3 } from "@browsercore/tls";

/**
 * Minimal TLS 1.3 profile for e2e traffic tests.
 * GREASE disabled: Node.js tls rejects unknown GREASE key-share groups,
 * while real servers ignore them. We test decryption, not GREASE handling.
 */
const TRAFFIC_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 11, 13, 16, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281],
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

        const transport = new TcpClientTransport(server.host, server.port);
        const conn = await connectTls({
            transport,
            crypto,
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

        const transport = new TcpClientTransport(server.host, server.port);
        const conn = await connectTls({
            transport,
            crypto,
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
