#!/usr/bin/env python3
"""Fresh re-probe chrome131 + safari170 through oracle, compare to captured bytes."""
import json, os, hashlib, struct
from curl_cffi import requests
OUT = "/Users/matte/projects/browsercore/testing/captures/_probe/output"

def parse_ja3(data):
    pos=5
    handshake_len=struct.unpack(">I", b'\x00'+data[6:9])[0]; pos=9
    end=9+handshake_len
    ver=struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
    pos+=32
    sid=data[pos]; pos+=1+sid
    csl=struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
    ciphers=[struct.unpack(">H", data[pos+i:pos+i+2])[0] for i in range(0,csl,2)]
    pos+=csl
    cl=data[pos]; pos+=1+cl
    exts=[]; sg=[]; ecpf=[]
    if pos+2<=end:
        el=struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
        eend=pos+el
        while pos+4<=eend:
            et=struct.unpack(">H", data[pos:pos+2])[0]
            xl=struct.unpack(">H", data[pos+2:pos+4])[0]; pos+=4
            exts.append(et)
            if et==0x000a and xl>=4:
                ll=struct.unpack(">H", data[pos:pos+2])[0]
                for i in range(0,ll,2): sg.append(struct.unpack(">H", data[pos+2+i:pos+4+i])[0])
            elif et==0x000b and xl>=1:
                ll=data[pos]
                for i in range(ll): ecpf.append(data[pos+1+i])
            pos+=xl
    return ver, ciphers, exts, sg, ecpf

def ja3hash(ver,ciphers,exts,sg,ecpf):
    s=",".join([str(ver), "-".join(str(c) for c in ciphers), "-".join(str(e) for e in exts), "-".join(str(g) for g in sg), "-".join(str(f) for f in ecpf)])
    return hashlib.md5(s.encode()).hexdigest(), s

RAW="/Users/matte/projects/browsercore/testing/captures/_probe/raw_bytes"

for profile, cap, label in [("chrome131","chrome-131","chrome-131"),("safari170","safari-17","safari-17")]:
    # fresh oracle probe
    r=requests.get("https://tls.peet.ws/api/all", impersonate=profile, timeout=30)
    od=r.json()
    # save fresh
    with open(os.path.join(OUT,f"{profile}_fresh.json"),"w") as f:
        json.dump(od,f,indent=2)
    oja3=od['tls']['ja3_hash']
    oja3str=od['tls']['ja3']
    oexts=[e['name'] for e in od['tls']['extensions']]
    # captured bytes
    with open(os.path.join(RAW,f"{cap}_client_hello.bin"),"rb") as f: d=f.read()
    ver,ciphers,exts,sg,ecpf=parse_ja3(d)
    cja3, cja3str = ja3hash(ver,ciphers,exts,sg,ecpf)
    # GREASE-stripped comparison
    def strip_grease(vals): return [v for v in vals if (v & 0x0f0f)!=0x0a0a]
    cja3_strip, cja3str_strip = ja3hash(ver, strip_grease(ciphers), strip_grease(exts), strip_grease(sg), ecpf)
    print(f"\n{label}:")
    print(f"  oracle  ja3={oja3}  str={oja3str}")
    print(f"  capture ja3={cja3}  str={cja3str}")
    print(f"  capture ja3 (GREASE-stripped)={cja3_strip}  str={cja3str_strip}")
    print(f"  match stripped? {cja3_strip==oja3}")
    print(f"  oracle exts: {oexts}")
    print(f"  capture exts: {exts}  (hex {[hex(e) for e in exts]})")
    # check SNI present in capture
    print(f"  capture has server_name(0)? {0 in exts}")
