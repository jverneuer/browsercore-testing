#!/usr/bin/env python3
"""
Transparent TLS relay that captures the authentic ClientHello bytes.

curl_cffi connects to https://tls.peet.ws:443 but we resolve tls.peet.ws to
127.0.0.1 (via a hosts redirect done by connecting to a local port with the
Host header set to tls.peet.ws). Actually simpler: we listen locally, and when
a client connects we:
  1. read the first flight (ClientHello) from the client — this has SNI=tls.peet.ws
     because curl_cffi derives SNI from the URL host, which we keep as tls.peet.ws.
  2. open a real TCP+TLS connection to the actual tls.peet.ws
  3. save the ClientHello bytes
  4. forward those bytes + relay the rest bidirectionally

The trick: curl_cffi gets the real tls.peet.ws IP via DNS but we intercept by
having curl_cffi connect through us. We do this by pointing curl_cffi at
https://tls.peet.ws/ and overriding resolution with a custom approach:
curl_cffi/requests allows `impersonate` and we can set the request to go to a
local socket via a pre-resolved address. Simplest reliable method: add an
entry mapping tls.peet.ws -> 127.0.0.1 using a tiny DNS override is complex.

Instead we use the CONNECT-less approach: curl_cffi lets us pass the URL as
https://tls.peet.ws and we intercept resolution by monkeypatching via a custom
transport is heavy. So we use the PROXY feature: set https proxy to our local
relay. With an HTTP CONNECT proxy, curl still sends SNI=tls.peet.ws inside the
tunnel and we relay raw bytes (no decryption), so we can sniff the ClientHello.
"""
import socket, threading, time, struct, json, os
from datetime import datetime, timezone
from curl_cffi import requests

RAW = "/Users/matte/projects/browsercore/testing/captures/_probe/raw_bytes"
os.makedirs(RAW, exist_ok=True)

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8443
REAL_HOST = "tls.peet.ws"
REAL_PORT = 443

def relay_capture(profile, outname):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    server.bind((RELAY_HOST, RELAY_PORT))
    server.listen(1)
    server.settimeout(15)

    client_hello = {"data": None}
    upstream_done = threading.Event()

    def accept_and_relay():
        try:
            client_sock, addr = server.accept()
            client_sock.settimeout(8)
            # Read initial flight from client (ClientHello).
            initial = b""
            try:
                while True:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    initial += chunk
                    if len(initial) >= 5:
                        rec_len = struct.unpack(">H", initial[3:5])[0]
                        if len(initial) >= 5 + rec_len:
                            break
            except socket.timeout:
                pass
            client_hello["data"] = initial

            # Now connect to the real server and forward.
            upstream = socket.create_connection((REAL_HOST, REAL_PORT), timeout=8)
            upstream.settimeout(8)
            upstream.sendall(initial)
            # Bidirectional relay until one side closes.
            def relay(src, dst):
                try:
                    while True:
                        d = src.recv(4096)
                        if not d:
                            break
                        dst.sendall(d)
                except Exception:
                    pass
            t1 = threading.Thread(target=relay, args=(client_sock, upstream))
            t2 = threading.Thread(target=relay, args=(upstream, client_sock))
            t1.start(); t2.start()
            t1.join(timeout=15); t2.join(timeout=15)
            try: client_sock.close()
            except Exception: pass
            try: upstream.close()
            except Exception: pass
        except Exception as e:
            client_hello["server_error"] = str(e)
        finally:
            try: server.close()
            except Exception: pass
            upstream_done.set()

    t = threading.Thread(target=accept_and_relay)
    t.start()
    time.sleep(0.4)

    # Use our relay as an HTTPS proxy. curl will do CONNECT tls.peet.ws:443
    # through 127.0.0.1:8443, then TLS with SNI=tls.peet.ws inside.
    proxy = f"http://{RELAY_HOST}:{RELAY_PORT}"
    captured_client_error = None
    try:
        # First do a plain GET through the proxy to the real host.
        requests.get(
            f"https://{REAL_HOST}/api/all",
            impersonate=profile,
            proxies={"https": proxy, "http": proxy},
            timeout=20,
            verify=True,
        )
    except Exception as e:
        captured_client_error = str(e)[:300]

    t.join(timeout=20)
    data = client_hello.get("data")
    if data:
        path = os.path.join(RAW, f"{outname}_client_hello.bin")
        with open(path, "wb") as f:
            f.write(data)
        print(f"  [{profile}] captured {len(data)} bytes -> {path}")
    else:
        print(f"  [{profile}] FAILED capture: {client_hello.get('server_error')} / {captured_client_error}")
    return data

PROFILES = [("chrome131", "chrome-131"), ("firefox133", "firefox-133"), ("safari170", "safari-17")]
for prof, outname in PROFILES:
    print(f"\n=== Relay-capturing {prof} -> {outname} ===")
    relay_capture(prof, outname)
    time.sleep(0.5)
