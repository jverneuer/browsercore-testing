#!/usr/bin/env python3
"""Compute JA3/JA4 of the synthetic golden hellos + extract supported_versions/peetprint from curl-cffi."""
import os, json, hashlib, struct

CAPTURES = "/Users/matte/projects/browsercore/testing/captures"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

def parse_client_hello_ja3(d):
    """Replicate our library's parseClientHello to get the 5 JA3 segments."""
    pos = 5  # TLS record wrapper assumed
    assert d[0] == 0x16 and d[5] == 0x01, "expected TLS-wrapped ClientHello"
    handshake_len = struct.unpack(">I", b'\x00'+d[6:9])[0]
    pos = 9
    end = 9 + handshake_len
    version = struct.unpack(">H", d[pos:pos+2])[0]; pos += 2
    random_bytes = d[pos:pos+32]; pos += 32
    sid_len = d[pos]; pos += 1 + sid_len
    cs_len = struct.unpack(">H", d[pos:pos+2])[0]; pos += 2
    ciphers = []
    for i in range(0, cs_len, 2):
        ciphers.append(struct.unpack(">H", d[pos+i:pos+i+2])[0])
    pos += cs_len
    comp_len = d[pos]; pos += 1 + comp_len
    ext_types=[]; supported_groups=[]; ec_pf=[]
    if pos + 2 <= end:
        ext_len = struct.unpack(">H", d[pos:pos+2])[0]; pos += 2
        ext_end = pos + ext_len
        while pos + 4 <= ext_end:
            et = struct.unpack(">H", d[pos:pos+2])[0]
            el = struct.unpack(">H", d[pos+2:pos+4])[0]
            pos += 4
            ext_types.append(et)
            if et == 0x000a and el >= 4:
                ll = struct.unpack(">H", d[pos:pos+2])[0]
                for i in range(0,ll,2): supported_groups.append(struct.unpack(">H", d[pos+2+i:pos+4+i])[0])
            elif et == 0x000b and el >= 1:
                ll = d[pos]
                for i in range(ll): ec_pf.append(d[pos+1+i])
            pos += el
    return version, ciphers, ext_types, supported_groups, ec_pf, random_bytes

def compute_ja3(segments):
    s = ",".join(segments)
    return hashlib.md5(s.encode()).hexdigest(), s

print("="*60)
print("GOLDEN CLIENT HELLO ANALYSIS")
print("="*60)
for name, path in [("chrome-140", "chrome-140/tls/client_hello.bin"), ("firefox-128", "firefox-128/tls/client_hello.bin")]:
    p = os.path.join(CAPTURES, path)
    with open(p,"rb") as f: d=f.read()
    ver, ciphers, exts, sg, ecpf, rnd = parse_client_hello_ja3(d)
    ja3_str = [str(ver), "-".join(str(c) for c in ciphers), "-".join(str(e) for e in exts), "-".join(str(g) for g in sg), "-".join(str(f) for f in ecpf)]
    md5, j3s = compute_ja3(ja3_str)
    print(f"\n{name} (synthetic):")
    print(f"  client_version=0x{ver:04x}")
    print(f"  random={rnd.hex()}")
    print(f"  ciphers ({len(ciphers)}): {[hex(c) for c in ciphers]}")
    print(f"  extensions ({len(exts)}): {[hex(e) for e in exts]}")
    print(f"  supported_groups: {[hex(g) for g in sg]}")
    print(f"  ec_point_formats: {ecpf}")
    print(f"  JA3 string: {j3s}")
    print(f"  JA3 hash: {md5}")
    print(f"  GREASE present: {'YES' if any((c&0xf0f)==0xa0f for c in ciphers) or any((e&0xf0f)==0xa0f for e in exts) else 'NO'}")

# Now extract supported_versions + peetprint from curl-cffi
print("\n\n" + "="*60)
print("SUPPORTED_VERSIONS + PEETPRINT from curl-cffi (real)")
print("="*60)
def extract_sv_pp(profile):
    with open(os.path.join(OUT, f"{profile}.json")) as f:
        d = json.load(f)
    tls = d["tls"]
    sv = None
    for e in tls.get("extensions", []):
        if "supported_versions" in e.get("name",""):
            sv = e.get("supported_versions")
            break
    return {
        "ja3_hash": tls.get("ja3_hash"),
        "ja4": tls.get("ja4"),
        "supported_versions": sv,
        "peetprint_hash": tls.get("peetprint_hash"),
    }

for p in ["chrome131","chrome133a","chrome136","firefox133","firefox135","safari170","safari180","safari184","edge99","chrome124"]:
    info = extract_sv_pp(p)
    print(f"{p:14s}: supported_versions={info['supported_versions']}  peetprint={info['peetprint_hash']}  ja3={info['ja3_hash']}  ja4={info['ja4']}")

# chrome-140 / firefox-128 synthetic peetprint equivalent
print("\nNOTE: synthetic golden hellos have no peetprint (they are stubs).")
