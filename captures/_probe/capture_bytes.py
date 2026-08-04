#!/usr/bin/env python3
"""
Capture real TLS ClientHello wire bytes from curl_cffi.

Strategy: run a local TCP server that accepts a connection, reads the first
chunk (which is always the TLS ClientHello), saves the raw bytes, then
closes. curl_cffi connects impersonating a target profile with verify=False
so it performs the TLS handshake against our server. We capture the bytes
before any handshake reply, so curl_cffi will error — but we already have
the ClientHello.
"""
import socket, ssl, threading, time, os, json, struct
from datetime import datetime, timezone
from curl_cffi import requests

BASE = "/Users/matte/projects/browsercore/testing/captures"
CAPTURED = os.path.join(BASE, "_probe", "raw_bytes")
os.makedirs(CAPTURED, exist_ok=True)

HOST = "127.0.0.1"

def capture_one(profile, port):
    """Server reads raw ClientHello bytes, then we trigger curl_cffi to connect."""
    captured = {"bytes": None, "error": None}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(1)
    server.settimeout(10)

    def accept_and_read():
        try:
            conn, addr = server.accept()
            conn.settimeout(5)
            # The ClientHello is the first thing the client sends.
            data = b""
            # Read enough to get the full ClientHello (usually 200-600 bytes).
            # We loop briefly to gather all initial flight bytes.
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # If we have a full TLS record header, check length for the first record.
                    if len(data) >= 5:
                        rec_len = struct.unpack(">H", data[3:5])[0]
                        if len(data) >= 5 + rec_len:
                            break  # got at least the first record fully
            except socket.timeout:
                pass
            captured["bytes"] = data
            try:
                conn.close()
            except Exception:
                pass
        except Exception as e:
            captured["error"] = f"server: {e}"
        finally:
            server.close()

    t = threading.Thread(target=accept_and_read)
    t.start()
    time.sleep(0.3)  # ensure server is listening

    # Trigger curl_cffi connection to our local server.
    url = f"https://{HOST}:{port}/"
    try:
        requests.get(url, impersonate=profile, verify=False, timeout=8,
                     headers={"Host": "example.com"})
    except Exception as e:
        # Expected — we don't complete the handshake. Record for diagnostics.
        captured["client_error"] = str(e)[:300]

    t.join(timeout=10)
    return captured

def parse_client_hello_summary(data):
    """Quick parse to confirm it looks like a real ClientHello, return byte len + first bytes."""
    if not data:
        return {"error": "no bytes captured"}
    info = {"total_bytes": len(data), "first_8": data[:8].hex()}
    if data[0] == 0x16:
        rec_ver = struct.unpack(">H", data[1:3])[0]
        rec_len = struct.unpack(">H", data[3:5])[0]
        hs_type = data[5] if len(data) > 5 else None
        info["record_version"] = f"0x{rec_ver:04x}"
        info["record_length"] = rec_len
        info["handshake_type"] = f"0x{hs_type:02x}" if hs_type is not None else None
        if hs_type == 0x01 and len(data) >= 11:
            hs_len = struct.unpack(">I", b'\x00'+data[6:9])[0]
            client_ver = struct.unpack(">H", data[9:11])[0]
            info["handshake_length"] = hs_len
            info["client_version"] = f"0x{client_ver:04x}"
            info["random"] = data[11:43].hex()
    return info

PROFILES = {
    "chrome-131": "chrome131",
    "firefox-133": "firefox133",
    "safari-17": "safari170",
}

PORT = 8443

for profile_name, impersonate in PROFILES.items():
    print(f"\n=== Capturing {profile_name} (impersonate={impersonate}) ===")
    cap = capture_one(impersonate, PORT)
    if cap["bytes"]:
        data = cap["bytes"]
        out_path = os.path.join(CAPTURED, f"{profile_name}_client_hello.bin")
        with open(out_path, "wb") as f:
            f.write(data)
        info = parse_client_hello_summary(data)
        print(f"  Captured {len(data)} bytes -> {out_path}")
        print(f"  Summary: {json.dumps(info, indent=4)}")
        # Also dump full hex (first 200 bytes)
        hexout = os.path.join(CAPTURED, f"{profile_name}_client_hello.hex")
        with open(hexout, "w") as f:
            for i in range(0, min(len(data), 512), 16):
                chunk = data[i:i+16]
                hexpart = " ".join(f"{b:02x}" for b in chunk)
                f.write(f"{i:04x}: {hexpart}\n")
    else:
        print(f"  FAILED: {cap.get('error')} / {cap.get('client_error')}")

print("\nDone.")
