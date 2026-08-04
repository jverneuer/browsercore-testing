#!/usr/bin/env python3
"""Probe chrome131 multiple times to confirm non-deterministic extension ordering."""
import json, os
from curl_cffi import requests
OUT="/Users/matte/projects/browsercore/testing/captures/_probe/output"

def exts_order(d):
    return [e['name'] for e in d['tls']['extensions']]

orders = []
for i in range(4):
    r = requests.get("https://tls.peet.ws/api/all", impersonate="chrome131", timeout=30)
    d = r.json()
    order = exts_order(d)
    ja3 = d['tls']['ja3_hash']
    orders.append((i, ja3, order))
    print(f"probe {i}: ja3={ja3}")
    print(f"  exts: {order}")

# Compare orders
base = orders[0][2]
print("\n=== Are all 4 identical? ===")
all_same = all(o[2]==base for o in orders)
print(f"All identical: {all_same}")
for i,(_,ja3,order) in enumerate(orders):
    if order != base:
        print(f"  probe {i} DIFFERS")
        # show first difference
        for j,(a,b) in enumerate(zip(base,order)):
            if a!=b:
                print(f"    first diff at index {j}: baseline={a} this={b}")
                break
