#!/usr/bin/env python3
"""
SOCKS5 proxy that captures the raw TLS ClientHello.

curl_cffi connects to the SOCKS5 proxy saying "connect to tls.peet.ws:443".
We open the real connection, complete the SOCKS handshake, then relay — but
capture the first TLS record (ClientHello) the client sends before forwarding
it upstream. Because the destination is tls.peet.ws, SNI is correct.
"""
import socket, struct, threading, time, os
from curl_cffi import requests

RAW = "/Users/matte/projects/browsercore/testing/captures/_probe/raw_bytes"
os.makedirs(RAW, exist_ok=True)

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8443
REAL_HOST = "tls.peet.ws"
REAL_PORT = 443

def socks_capture(profile, outname):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    server.bind((RELAY_HOST, RELAY_PORT))
    server.listen(1)
    server.settimeout(20)

    result = {"data": None}

    def handle():
        try:
            client, addr = server.accept()
            client.settimeout(10)
            # ---- SOCKS5 handshake ----
            # Client sends: VER=0x05, NAUTH, auth methods
            hdr = client.recv(2)
            if not hdr or hdr[0] != 0x05:
                client.close(); return
            nmethods = hdr[1]
            client.recv(nmethods)  # read auth methods
            # Reply: no auth required
            client.sendall(b'\x05\x00')
            # Client request: VER, CMD=0x01(connect), RSV, ATYP, DST.ADDR, DST.PORT
            req = client.recv(4)
            if not req or req[0] != 0x05 or req[1] != 0x01:
                client.close(); return
            atyp = req[3]
            if atyp == 0x01:  # IPv4
                dst = socket.inet_ntoa(client.recv(4))
            elif atyp == 0x04:  # IPv6
                dst = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            elif atyp == 0x03:  # domain
                dlen = client.recv(1)[0]
                dst = client.recv(dlen).decode()
            else:
                client.close(); return
            port_bytes = client.recv(2)
            dst_port = struct.unpack(">H", port_bytes)[0]
            # Connect to the real destination
            upstream = socket.create_connection((REAL_HOST, REAL_PORT), timeout=10)
            upstream.settimeout(10)
            # SOCKS success reply (bound addr = 0.0.0.0:0)
            client.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack(">H", 0))

            # ---- Now relay, capturing client's first TLS flight ----
            initial = b""
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    initial += chunk
                    if len(initial) >= 5:
                        rec_len = struct.unpack(">H", initial[3:5])[0]
                        if len(initial) >= 5 + rec_len:
                            break
            except socket.timeout:
                pass
            result["data"] = initial
            # forward captured bytes + continue relay
            upstream.sendall(initial)
            def relay(src, dst_s):
                try:
                    while True:
                        d = src.recv(4096)
                        if not d: break
                        dst_s.sendall(d)
                except Exception:
                    pass
            t1 = threading.Thread(target=relay, args=(client, upstream))
            t2 = threading.Thread(target=relay, args=(upstream, client))
            t1.start(); t2.start()
            t1.join(timeout=20); t2.join(timeout=20)
            try: client.close()
            except Exception: pass
            try: upstream.close()
            except Exception: pass
        except Exception as e:
            result["server_error"] = str(e)
        finally:
            try: server.close()
            except Exception: pass

    t = threading.Thread(target=handle)
    t.start()
    time.sleep(0.4)

    proxy = f"socks5h://{RELAY_HOST}:{RELAY_PORT}"
    try:
        requests.get(
            f"https://{REAL_HOST}/api/all",
            impersonate=profile,
            proxies={"https": proxy, "http": proxy},
            timeout=25,
            verify=True,
        )
    except Exception as e:
        result["client_error"] = str(e)[:300]

    t.join(timeout=25)
    data = result.get("data")
    if data:
        path = os.path.join(RAW, f"{outname}_client_hello.bin")
        with open(path, "wb") as f:
            f.write(data)
        print(f"  [{profile}] captured {len(data)} bytes -> {path}")
    else:
        print(f"  [{profile}] FAILED: {result.get('server_error')} / {result.get('client_error')}")
    return data

PROFILES = [("chrome131", "chrome-131"), ("firefox133", "firefox-133"), ("safari170", "safari-17")]
for prof, outname in PROFILES:
    print(f"\n=== SOCKS-capturing {prof} -> {outname} ===")
    socks_capture(prof, outname)
    time.sleep(0.5)
