#!/usr/bin/env python3
"""Verify captured ClientHello bytes reproduce oracle JA3/JA4."""
import os, json, hashlib, struct

RAW = "/Users/matte/projects/browsercore/testing/captures/_probe/raw_bytes"
OUT = "/Users/matte/projects/browsercore/testing/captures/_probe/output"

# Replicate our library's exact parseClientHello + computeJa3
def parse_client_hello(d):
    pos = 5  # TLS record wrapper
    assert d[0] == 0x16 and d[5] == 0x01
    handshake_len = struct.unpack(">I", b'\x00'+d[6:9])[0]
    pos = 9
    end = 9 + handshake_len
    version = struct.unpack(">H", d[pos:pos+2])[0]; pos += 2
    pos += 32  # random
    sid_len = d[pos]; pos += 1 + sid_len
    cs_len = struct.unpack(">H", d[pos:pos+2])[0]; pos += 2
    ciphers = []
    for i in range(0, cs_len, 2):
        ciphers.append(struct.unpack(">H", d[pos+i:pos+i+2])[0])
    pos += cs_len
    comp_len = d[pos]; pos += 1 + comp_len
    ext_types=[]; sg=[]; ecpf=[]
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
                for i in range(0,ll,2): sg.append(struct.unpack(">H", d[pos+2+i:pos+4+i])[0])
            elif et == 0x000b and el >= 1:
                ll = d[pos]
                for i in range(ll): ecpf.append(d[pos+1+i])
            pos += el
    return version, ciphers, ext_types, sg, ecpf

def ja3(segments):
    s = ",".join(segments)
    return hashlib.md5(s.encode()).hexdigest(), s

MAP = [("chrome-131", "chrome131"), ("firefox-133", "firefox133"), ("safari-17", "safari170")]

for cap_name, oracle_name in MAP:
    with open(os.path.join(RAW, f"{cap_name}_client_hello.bin"),"rb") as f:
        d = f.read()
    ver, ciphers, exts, sg, ecpf = parse_client_hello(d)
    # JA3 segments use decimal of GREASE as-is (GREASE values included in JA3 string)
    j3s = [str(ver), "-".join(str(c) for c in ciphers), "-".join(str(e) for e in exts), "-".join(str(g) for g in sg), "-".join(str(f) for f in ecpf)]
    md5, j3str = ja3(j3s)
    # oracle values
    od = json.load(open(os.path.join(OUT, f"{oracle_name}.json")))
    oracle_ja3 = od['tls']['ja3_hash']
    oracle_ja3_str = od['tls']['ja3']
    match = "MATCH" if md5 == oracle_ja3 else "MISMATCH"
    print(f"{cap_name}: captured_ja3={md5} oracle_ja3={oracle_ja3}  [{match}]")
    print(f"  captured JA3 str: {j3str}")
    print(f"  oracle  JA3 str:  {oracle_ja3_str}")
    print(f"  version=0x{ver:04x} ciphers={len(ciphers)} exts={len(exts)}")
    # GREASE check
    grease_exts = [hex(e) for e in exts if (e & 0x0f0f) == 0x0a0a]
    grease_ciphers = [hex(c) for c in ciphers if (c & 0x0f0f) == 0x0a0a]
    print(f"  GREASE ciphers: {grease_ciphers}  GREASE exts: {grease_exts}")
    print()
