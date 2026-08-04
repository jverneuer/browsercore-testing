#!/usr/bin/env python3
"""Inspect existing golden capture binaries: hex dump + attempt JA3 parse."""
import os, json
CAPTURES = "/Users/matte/projects/browsercore/testing/captures"

def hexdump(path, maxbytes=200):
    with open(path, "rb") as f:
        data = f.read(maxbytes)
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}: {hexpart:<48s} {ascpart}")
    return "\n".join(out)

# Load + dump each golden
for rel in ["chrome-140/tls/client_hello.bin", "firefox-128/tls/client_hello.bin", "chrome-140/http2/settings.bin"]:
    p = os.path.join(CAPTURES, rel)
    print(f"\n{'='*60}")
    print(f"FILE: {rel}  ({os.path.getsize(p)} bytes)")
    print(f"{'='*60}")
    print(hexdump(p))
    meta = p.replace(".bin", ".meta.json")
    if os.path.exists(meta):
        with open(meta) as f:
            m = json.load(f)
        print(f"  meta.profile={m.get('profile')} protocol={m.get('protocol')} record={m.get('record')} randomizedFields={m.get('randomizedFields')}")

# Try to parse chrome-140 client hello as TLS
print("\n\n=== ATTEMPT TLS PARSE chrome-140 client_hello.bin ===")
import struct
p = os.path.join(CAPTURES, "chrome-140/tls/client_hello.bin")
with open(p,"rb") as f:
    d = f.read()
print(f"First 4 bytes: {d[:4].hex()}")
print(f"First byte: 0x{d[0]:02x} ({'TLS record 0x16' if d[0]==0x16 else 'handshake 0x01' if d[0]==0x01 else 'other'})")
# Try treating as TLS record
if d[0] == 0x16:
    rec_ver = struct.unpack(">H", d[1:3])[0]
    rec_len = struct.unpack(">H", d[3:5])[0]
    hs_type = d[5]
    print(f"  record version=0x{rec_ver:04x} record_len={rec_len} handshake_type=0x{hs_type:02x}")
    if hs_type == 0x01:
        hs_len = struct.unpack(">I", b'\x00'+d[6:9])[0]
        client_ver = struct.unpack(">H", d[9:11])[0]
        print(f"  handshake_len={hs_len} client_version=0x{client_ver:04x}")
        print(f"  random (32 bytes): {d[11:43].hex()}")
        print(f"  Remaining after random ({len(d)-43} bytes): {d[43:].hex()}")
elif d[0] == 0x01:
    print("Bare handshake")
else:
    print("NOT a standard TLS record/handshake header")
    # Maybe it's just extension/cipher data? Show interpretation
    print("Treating raw: version bytes:", d[:2].hex())
