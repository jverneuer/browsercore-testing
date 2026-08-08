/**
 * E2E traffic server for Bug 6 (AES-128-GCM record decryption) regression.
 *
 * Extends the sink-server pattern: performs a **real** TLS 1.3 handshake
 * against the @browsercore/tls client stack, then serves an encrypted HTTP
 * response. The client must decrypt the full server flight (handshake +
 * application data) — if AEAD key derivation, nonce construction, or record
 * parsing is wrong, decryption fails and the fetch throws.
 *
 * This is the deterministic, network-free reproduction for Bug 6: the same
 * TLS code path that fails against example.com fails here, but without a
 * network dependency.
 */

import { createServer, type Server, type Socket } from "node:net";
import { createSecureContext, TLSSocket, type SecureContext } from "node:tls";
import { generateSelfSignedCert } from "./cert-gen.js";

/** HTTP response the server sends after a successful handshake. */
const HTTP_RESPONSE = [
    "HTTP/1.1 200 OK",
    "Content-Type: text/plain",
    "X-Traffic-Gate: bug6",
    "Content-Length: 19",
    "",
    "TRAFFIC_GATE_OK_BUG6",
].join("\r\n");

/** Result of a completed handshake against the traffic server. */
export interface TrafficResult {
    /** Negotiated protocol version, e.g. "TLSv1.3". */
    readonly protocolVersion: string;
    /** Negotiated cipher suite. */
    readonly cipherSuite: string;
    /** ALPN protocol negotiated, or null. */
    readonly alpnProtocol: string | null;
    /** Wall-clock handshake duration in milliseconds. */
    readonly handshakeDurationMs: number;
}

type HandshakeState =
    | { state: "idle" }
    | { state: "handshaking"; readonly startedAt: number }
    | { state: "done"; readonly result: TrafficResult }
    | { state: "failed"; readonly error: Error };

/**
 * Single-shot TLS 1.3 traffic server. Performs a real handshake, then sends
 * an encrypted HTTP response the client must decrypt.
 */
export class TrafficServer {
    private readonly server: Server;
    private readonly ctx: SecureContext;
    private state: HandshakeState = { state: "idle" };
    private waiters: Array<(result: TrafficResult) => void> = [];
    private failers: Array<(err: Error) => void> = [];

    public readonly host: string;
    public readonly port: number;

    private constructor(server: Server, ctx: SecureContext, host: string, port: number) {
        this.server = server;
        this.ctx = ctx;
        this.host = host;
        this.port = port;
    }

    /** Start listening on an ephemeral port on 127.0.0.1. */
    static start(): Promise<TrafficServer> {
        const { certDer, keyPem } = generateSelfSignedCert(["localhost"], ["127.0.0.1"], 1);
        const ctx = createSecureContext({
            key: keyPem,
            cert: derToPem(certDer, "CERTIFICATE"),
        });

        return new Promise((resolve, reject) => {
            const server = createServer({ allowHalfOpen: false });
            server.maxConnections = 1;
            server.on("error", reject);
            server.listen(0, "127.0.0.1", () => {
                const addr = server.address();
                if (addr === null || typeof addr === "string") {
                    reject(new Error("traffic server did not bind"));
                    return;
                }
                const traffic = new TrafficServer(server, ctx, addr.address, addr.port);
                traffic.attach();
                resolve(traffic);
            });
        });
    }

    private attach(): void {
        this.server.on("connection", (socket) => this.onConnection(socket));
    }

    private onConnection(rawSocket: Socket): void {
        if (this.state.state !== "idle") {
            rawSocket.destroy();
            return;
        }

        const startedAt = Date.now();
        this.state = { state: "handshaking", startedAt };

        const tlsSocket = new TLSSocket(rawSocket, {
            isServer: true,
            secureContext: this.ctx,
            requestCert: false,
            ALPNProtocols: ["h2", "http/1.1"],
        });

        tlsSocket.on("secure", () => {
            // Handshake completed. Now send the encrypted HTTP response.
            // The client must decrypt this to read the body — this is what
            // exercises the Bug 6 path.
            tlsSocket.write(HTTP_RESPONSE, () => {
                const result: TrafficResult = {
                    protocolVersion: tlsSocket.getProtocol() ?? "unknown",
                    cipherSuite: tlsSocket.getCipher().name,
                    alpnProtocol: narrowServerName(tlsSocket.alpnProtocol),
                    handshakeDurationMs: Date.now() - startedAt,
                };
                this.done(result);
            });
        });

        tlsSocket.on("error", (err) => {
            this.fail(new Error(`TLS handshake failed: ${err.message}`, { cause: err }));
        });

        tlsSocket.on("close", () => {
            if (this.state.state !== "done") {
                this.fail(new Error("socket closed before handshake completed"));
            }
        });
    }

    private done(result: TrafficResult): void {
        if (this.state.state === "done") return;
        this.state = { state: "done", result };
        const w = this.waiters;
        this.waiters = [];
        this.failers = [];
        for (const resolve of w) resolve(result);
    }

    private fail(error: Error): void {
        if (this.state.state === "done") return;
        this.state = { state: "failed", error };
        const f = this.failers;
        this.failers = [];
        this.waiters = [];
        for (const reject of f) reject(error);
    }

    /** Resolve once handshake completes. */
    waitForHandshake(timeoutMs = 5000): Promise<TrafficResult> {
        if (this.state.state === "done") return Promise.resolve(this.state.result);
        if (this.state.state === "failed") return Promise.reject(this.state.error);
        return new Promise((resolve, reject) => {
            let timer: NodeJS.Timeout | undefined;
            this.waiters.push((r) => { if (timer) clearTimeout(timer); resolve(r); });
            this.failers.push((e) => { if (timer) clearTimeout(timer); reject(e); });
            timer = setTimeout(() => this.fail(new Error("waitForHandshake timed out")), timeoutMs);
        });
    }

    stop(): Promise<void> {
        this.fail(new Error("traffic server stopped"));
        return new Promise((resolve, reject) => {
            this.server.close((err) => { if (err) reject(err); else resolve(); });
        });
    }
}

function narrowServerName(value: string | false | null): string | null {
    return typeof value === "string" ? value : null;
}

function derToPem(der: Uint8Array, label: string): string {
    const b64 = Buffer.from(der).toString("base64");
    const lines = [`-----BEGIN ${label}-----`];
    for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
    lines.push(`-----END ${label}-----`);
    return lines.join("\n");
}
