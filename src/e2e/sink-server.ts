/**
 * E2E TLS sink server for live handshake verification.
 *
 * Performs a **real** TLS 1.3 handshake against the `@browsercore/tls` client
 * stack and returns the raw ClientHello bytes it saw on the wire — captured
 * *before* Node's `tls` module parses them. This is the missing test oracle:
 * every other TLS test in the stack runs against an in-process fixture; the
 * sink exercises the full stack end-to-end over a real TCP socket.
 *
 * ## Two-socket tap
 *
 * Node's `tls` module parses the ClientHello before user code can see it, so
 * the sink uses a two-socket tap (plan §2.3, Approach A):
 *
 * 1. A raw `node:net` server accepts the connection and pauses the socket.
 * 2. It buffers the first bytes (the ClientHello TLS record) by reading until
 *    the record length is satisfied.
 * 3. It unshifts the buffer back onto the socket and wraps the socket in a
 *    `tls.TLSSocket` (server-side) with a freshly generated self-signed
 *    ECDSA P-256 cert.
 * 4. The handshake completes; the captured bytes + parsed inspection are
 *    returned via {@link TlsSinkServer.waitForHandshake}.
 *
 * The sink is single-shot by design: {@link TlsSinkServer.waitForHandshake}
 * resolves on the first completed handshake. Tests create a fresh sink per
 * case (ephemeral port, `maxConnections: 1`).
 */

import { createServer, type Server, type Socket } from "node:net";
import { createSecureContext, TLSSocket, type SecureContext } from "node:tls";
import { generateSelfSignedCert } from "./cert-gen.js";

/** Captured ClientHello — raw bytes + wall-clock capture time. */
export interface ClientHelloCapture {
    /** Full TLS record(s) as seen on the wire (record header + handshake). */
    readonly raw: Uint8Array;
    /** Epoch milliseconds when the capture completed. */
    readonly receivedAt: number;
}

/** Result of a completed handshake against the sink. */
export interface HandshakeResult {
    /** The raw ClientHello the sink captured before TLS parsing. */
    readonly clientHello: ClientHelloCapture;
    /** Negotiated protocol version, e.g. "TLSv1.3". */
    readonly protocolVersion: string;
    /** Negotiated cipher suite, e.g. "TLS_AES_128_GCM_SHA256". */
    readonly cipherSuite: string;
    /** ALPN protocol negotiated, or null if none. */
    readonly alpnProtocol: string | null;
    /** SNI hostname the client sent, or null if omitted. */
    readonly serverName: string | null;
    /** Wall-clock handshake duration in milliseconds. */
    readonly handshakeDurationMs: number;
}

/** Internal discriminated state of the sink's single handshake slot. */
type HandshakeState =
    | { state: "idle" }
    | { state: "capturing"; readonly startedAt: number }
    | { state: "handshaking"; readonly capture: ClientHelloCapture; readonly startedAt: number }
    | { state: "done"; readonly result: HandshakeResult }
    | { state: "failed"; readonly error: Error };

/**
 * Lightweight TLS 1.3 sink server.
 *
 * Not a general-purpose TLS server — it exists only to confirm a real
 * handshake completes and to return the wire bytes it saw. All assertions
 * live in the *test*; the sink just reports.
 */
export class TlsSinkServer {
    private readonly server: Server;
    private readonly ctx: SecureContext;
    private state: HandshakeState = { state: "idle" };
    private waiters: Array<(result: HandshakeResult) => void> = [];
    private failers: Array<(err: Error) => void> = [];

    /** Host the sink listens on (always 127.0.0.1). */
    public readonly host: string;
    /** Ephemeral port the sink listens on. */
    public readonly port: number;

    /** ALPN protocols the sink negotiates (empty = no ALPN negotiation). */
    private readonly alpnProtocols: readonly string[];

    private constructor(
        server: Server,
        ctx: SecureContext,
        host: string,
        port: number,
        alpnProtocols: readonly string[],
    ) {
        this.server = server;
        this.ctx = ctx;
        this.host = host;
        this.port = port;
        this.alpnProtocols = alpnProtocols;
    }

    /**
     * Start listening on an ephemeral port on 127.0.0.1.
     *
     * The returned sink is ready to accept one connection. The self-signed
     * cert is generated at call time (throwaway — valid for 1 day).
     *
     * @param opts Optional configuration — ALPN protocols the sink should
     *   negotiate (chooses the first client-offered protocol that matches).
     */
    static start(opts: { readonly alpnProtocols?: readonly string[] } = {}): Promise<TlsSinkServer> {
        const { certDer, keyPem } = generateSelfSignedCert(["localhost"], ["127.0.0.1"], 1);
        const ctx = createSecureContext({
            key: keyPem,
            cert: derToPem(certDer, "CERTIFICATE"),
        });

        return new Promise((resolve, reject) => {
            const server = createServer({ allowHalfOpen: false });
            server.maxConnections = 1;

            server.on("error", (err) => {
                // If we haven't finished constructing the sink, reject start.
                reject(err);
            });

            server.listen(0, "127.0.0.1", () => {
                const addr = server.address();
                if (addr === null || typeof addr === "string") {
                    reject(new Error("sink server did not bind to an ephemeral port"));
                    return;
                }
                const sink = new TlsSinkServer(server, ctx, addr.address, addr.port, opts.alpnProtocols ?? []);
                sink.attach();
                resolve(sink);
            });
        });
    }

    /** Wire up the server's connection handler. Must be called once. */
    private attach(): void {
        this.server.on("connection", (socket) => this.onConnection(socket));
    }

    /**
     * Handle an incoming TCP connection: buffer the ClientHello, then hand the
     * socket to a server-side TLSSocket for a real handshake.
     */
    private onConnection(rawSocket: Socket): void {
        // Guard: only one handshake per sink.
        if (this.state.state !== "idle") {
            rawSocket.destroy();
            return;
        }

        const startedAt = Date.now();
        this.state = { state: "capturing", startedAt };

        const chunks: Uint8Array[] = [];
        let totalBuffered = 0;

        // Pause the socket so data accumulates in Node's internal buffer and we
        // can read it deterministically before the TLSSocket consumes it.
        rawSocket.pause();

        /**
         * Read chunks until we have at least one complete TLS record. A TLS
         * record is 5 header bytes + `length` bytes of fragment. The
         * ClientHello typically arrives in a single segment, but we loop to be
         * robust to fragmentation.
         */
        const tryCapture = (): Uint8Array | null => {
            if (totalBuffered < 5) return null;
            const recordLen = 5 + ((chunks[0]![3]! << 8) | chunks[0]![4]!);
            if (totalBuffered < recordLen) return null;
            // Concatenate the buffered chunks and slice to the record boundary.
            const flat = flattenChunks(chunks, totalBuffered);
            return flat.subarray(0, recordLen);
        };

        const onData = (chunk: Uint8Array) => {
            chunks.push(chunk);
            totalBuffered += chunk.length;
            const capture = tryCapture();
            if (capture !== null) {
                rawSocket.removeListener("data", onData);
                this.onClientHello(rawSocket, capture, startedAt);
            }
        };

        rawSocket.on("data", onData);
        rawSocket.on("error", (err) => this.fail(err));
        rawSocket.on("close", () => {
            // If we closed before completing the handshake, fail any waiter.
            if (this.state.state !== "done") {
                this.fail(new Error("socket closed before handshake completed"));
            }
        });

        // Resume flow so the data handler fires.
        rawSocket.resume();
    }

    /**
     * We have the raw ClientHello. Unshift it back onto the socket and wrap
     * the socket in a server-side TLSSocket to complete the handshake.
     */
    private onClientHello(rawSocket: Socket, capture: Uint8Array, startedAt: number): void {
        // Wrap the raw socket in a TLSSocket BEFORE unshifting. The TLSSocket
        // attaches its own `data` listener on construction; only after that
        // listener is in place does unshift deliver the captured bytes straight
        // into the TLS layer. Unshifting first leaves the bytes buffered with
        // no listener to consume them, so the handshake never starts.
        const tlsSocket = new TLSSocket(rawSocket, {
            isServer: true,
            secureContext: this.ctx,
            // Request but do not require a client cert — keeps the sink simple.
            requestCert: false,
            ALPNProtocols: this.alpnProtocols.length > 0 ? this.alpnProtocols : undefined,
        });

        // Now push the captured bytes back; the TLSSocket reads them as its
        // first input and begins the handshake.
        rawSocket.unshift(capture);

        const clientHello: ClientHelloCapture = {
            raw: capture,
            receivedAt: Date.now(),
        };
        this.state = { state: "handshaking", capture: clientHello, startedAt };

        tlsSocket.on("secure", () => {
            // The secure event fires once the handshake is verified.
            const result: HandshakeResult = {
                clientHello,
                protocolVersion: tlsSocket.getProtocol() ?? "unknown",
                cipherSuite: tlsSocket.getCipher().name,
                alpnProtocol: narrowServerName(tlsSocket.alpnProtocol),
                serverName: narrowServerName(tlsSocket.servername),
                handshakeDurationMs: Date.now() - startedAt,
            };
            this.done(result);
            // Close the connection after reporting — single-shot sink.
            tlsSocket.end();
        });

        tlsSocket.on("error", (err) => {
            // Distinguish handshake rejection from transport errors.
            this.fail(new Error(`TLS handshake failed: ${err.message}`, { cause: err }));
        });
    }

    /** Transition to the done state and resolve any waiters. */
    private done(result: HandshakeResult): void {
        if (this.state.state === "done") return;
        this.state = { state: "done", result };
        const w = this.waiters;
        this.waiters = [];
        this.failers = [];
        for (const resolve of w) resolve(result);
    }

    /** Transition to the failed state and reject any waiters. */
    private fail(error: Error): void {
        if (this.state.state === "done") return;
        this.state = { state: "failed", error };
        const f = this.failers;
        this.failers = [];
        this.waiters = [];
        for (const reject of f) reject(error);
    }

    /**
     * Resolve once a ClientHello has been captured and the handshake completed.
     *
     * @param timeoutMs Max wait in milliseconds (default 5000). The sink is
     *   single-shot — only the first handshake resolves this promise.
     * @throws {Error} on timeout or handshake failure.
     */
    waitForHandshake(timeoutMs = 5000): Promise<HandshakeResult> {
        if (this.state.state === "done") {
            return Promise.resolve(this.state.result);
        }
        if (this.state.state === "failed") {
            return Promise.reject(this.state.error);
        }
        return new Promise((resolve, reject) => {
            let timer: NodeJS.Timeout | undefined;
            this.waiters.push((result) => {
                if (timer !== undefined) clearTimeout(timer);
                resolve(result);
            });
            this.failers.push((err) => {
                if (timer !== undefined) clearTimeout(timer);
                reject(err);
            });
            timer = setTimeout(() => {
                this.fail(new Error(`waitForHandshake timed out after ${timeoutMs}ms`));
            }, timeoutMs);
        });
    }

    /** Stop the server. Resolves once the underlying socket is closed. */
    stop(): Promise<void> {
        // Reject any pending waiters so callers don't hang.
        this.fail(new Error("sink server stopped"));
        return new Promise((resolve, reject) => {
            this.server.close((err) => {
                if (err !== undefined) reject(err);
                else resolve();
            });
        });
    }
}

// --- Byte helpers -------------------------------------------------------

/** Concatenate an array of chunks into a single buffer of `total` bytes. */
function flattenChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

/**
 * Coerce Node's `TLSSocket.servername` (`string | false | null`) to
 * `string | null`. `false` means SNI was requested but not matched; `null`
 * means no SNI was sent. Both map to "no usable servername" here.
 */
function narrowServerName(value: string | false | null): string | null {
    return typeof value === "string" ? value : null;
}

/**
 * Convert a DER-encoded object to PEM (base64 with 64-char lines + headers).
 * Used to feed the self-signed cert into `tls.createSecureContext`, which
 * expects PEM for the `cert` option.
 */
function derToPem(der: Uint8Array, label: string): string {
    const b64 = Buffer.from(der).toString("base64");
    const lines: string[] = [`-----BEGIN ${label}-----`];
    for (let i = 0; i < b64.length; i += 64) {
        lines.push(b64.slice(i, i + 64));
    }
    lines.push(`-----END ${label}-----`);
    return lines.join("\n");
}
