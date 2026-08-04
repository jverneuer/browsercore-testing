#!/usr/bin/env python3
import json
d = json.load(open('/Users/matte/projects/browsercore/testing/captures/_probe/output/chrome131.json'))
for e in d['tls']['extensions']:
    if 'supported_versions' in e.get('name',''):
        print('=== supported_versions extension raw keys ===')
        print(list(e.keys()))
        print(json.dumps(e, indent=2))
        break
print()
print('tls keys:', list(d['tls'].keys()))
print('peetprint_hash:', d['tls'].get('peetprint_hash'))
# check if there's a peetprint string field anywhere
for k,v in d['tls'].items():
    if 'peet' in k.lower():
        print(f'  {k}: {str(v)[:200]}')
