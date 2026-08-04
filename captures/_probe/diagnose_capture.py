#!/usr/bin/env python3
"""Carefully parse captured chrome-131 ClientHello and compare extension names to oracle."""
import os, json, struct

RAW = "/Users/matte/projects/browsercore/testing/captures/_probe/raw_bytes"
OUT = "/Users/matte/projects/browsercore/testing/captures/_probe/output"

EXT_NAMES = {0:"server_name",5:"status_request",10:"supported_groups",11:"ec_point_formats",
             13:"signature_algorithms",16:"ALPN",18:"signed_certificate_timestamp",
             21:"padding",23:"extended_master_secret",27:"compress_certificate",
             28:"record_size_limit",34:"delegated_credentials",35:"session_ticket",
             43:"supported_versions",45:"psk_key_exchange_modes",51:"key_share",
             65037:"ECH",65281:"renegotiation_info",17513:"application_settings_old",
             17613:"application_settings"}
def is_grease(v): return (v & 0x0f0f) == 0x0a0a

def parse_full(data):
    """Parse assuming single TLS record, return detailed extension list."""
    assert data[0]==0x16 and data[5]==0x01, f"not a CH record: {data[:6].hex()}"
    rec_len = struct.unpack(">H", data[3:5])[0]
    hs_len = struct.unpack(">I", b'\x00'+data[6:9])[0]
    pos = 9
    end = 9 + hs_len
    ver = struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
    rand = data[pos:pos+32]; pos+=32
    sid_len=data[pos]; pos+=1+sid_len
    cs_len = struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
    ciphers=[struct.unpack(">H", data[pos+i:pos+i+2])[0] for i in range(0,cs_len,2)]
    pos+=cs_len
    comp_len=data[pos]; pos+=1+comp_len
    exts=[]
    if pos+2<=end:
        ext_len=struct.unpack(">H", data[pos:pos+2])[0]; pos+=2
        ext_end=pos+ext_len
        while pos+4<=ext_end:
            et=struct.unpack(">H", data[pos:pos+2])[0]
            el=struct.unpack(">H", data[pos+2:pos+4])[0]
            pos+=4
            exts.append((et, el, pos))  # pos = ext data start
            pos+=el
        print(f"  ext_end={ext_end} final pos={pos} record_end={5+rec_len}")
    return ver, ciphers, exts

with open(os.path.join(RAW,"chrome-131_client_hello.bin"),"rb") as f:
    d=f.read()
ver, ciphers, exts = parse_full(d)
print(f"chrome-131 captured: ver=0x{ver:04x} {len(ciphers)} ciphers, {len(exts)} extensions")
print(f"  last byte index used: ext data end check")
print("\n  Extension list (with GREASE flag):")
for et,el,dp in exts:
    g = " [GREASE]" if is_grease(et) else ""
    print(f"    0x{et:04x} ({et}) = {EXT_NAMES.get(et,'?')}  len={el}{g}")

# Compare to oracle
od = json.load(open(os.path.join(OUT,"chrome131.json")))
oracle_ext_names = [e['name'] for e in od['tls']['extensions']]
print(f"\n  Oracle extension names ({len(oracle_ext_names)}):")
for n in oracle_ext_names:
    print(f"    {n}")
