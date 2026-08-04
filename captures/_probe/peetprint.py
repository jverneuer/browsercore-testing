#!/usr/bin/env python3
import json, os
OUT = "/Users/matte/projects/browsercore/testing/captures/_probe/output"

def get_sv(ext_list):
    for e in ext_list:
        if 'supported_versions' in e.get('name',''):
            return e.get('versions', [])
    return None

PROFILES = ["chrome124","chrome131","chrome133a","chrome136","chrome120","chrome119","chrome116","chrome110",
            "firefox133","firefox135",
            "safari170","safari180","safari184",
            "edge99","edge101"]

print(f"{'profile':14s} | supported_versions")
print("-"*90)
for p in PROFILES:
    d = json.load(open(os.path.join(OUT, f"{p}.json")))
    tls = d['tls']
    sv = get_sv(tls['extensions'])
    print(f"{p:14s} | {sv}")

print("\n\n=== PEETPRINT (full ordering fingerprint) ===")
for p in PROFILES:
    d = json.load(open(os.path.join(OUT, f"{p}.json")))
    pp = d['tls'].get('peetprint','')
    print(f"\n{p}:")
    print(f"  {pp}")

print("\n\n=== SETTINGS + WINDOW_UPDATE + AKAMAI (for settings.frame divergence) ===")
for p in PROFILES:
    d = json.load(open(os.path.join(OUT, f"{p}.json")))
    h2 = d['http2']
    settings = wu = None
    for fr in h2.get('sent_frames',[]):
        if fr['frame_type']=='SETTINGS': settings = fr.get('settings')
        if fr['frame_type']=='WINDOW_UPDATE': wu = fr.get('increment')
    print(f"{p:14s} | SETTINGS={settings}  WINDOW_UPDATE={wu}  akamai={h2.get('akamai_fingerprint')}")
