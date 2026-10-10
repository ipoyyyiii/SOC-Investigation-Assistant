#!/usr/bin/env python3
"""BOTS harness — sample real Splunk/Sysmon attack events, replay to webhook, score pipeline.
Criteria (all deterministic, no LLM): stored / attack_type / parent+command preserved / hash TI cached / incident+risk produced.
"""
import json, os, gzip, random, subprocess, sys, time, urllib.request

random.seed(11)
KEY = os.environ.get('SOC_KEY', 'REPLACE_WITH_ENV')
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10

# 1) sample process-creation events WITH full observables
picked = []
with gzip.open('/tmp/bots/sysmon.json.gz', 'rt', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        if len(picked) >= N * 30:
            break
        try:
            o = json.loads(line)['result']
        except Exception:
            continue
        if o.get('EventCode') != '1':
            continue
        cl, pi, img = o.get('CommandLine'), o.get('ParentImage'), o.get('Image')
        if cl and pi and img and len(cl) > 8:
            picked.append(o)

# spread across the attack timeline + prefer suspicious parents
def suspicious(o):
    cl = (o.get('CommandLine') or '').lower()
    pi = (o.get('ParentImage') or '').lower()
    strong = ('appdata', 'temp', 'public', 'powershell', '-enc', 'iex', 'invoke', 'schtasks', 'vssadmin', 'wmic', 'net user', 'reg add', 'mimikatz', 'psexec', 'lsass', 'sam hive', 'nc.exe', 'bitsadmin', 'certutil')
    return sum(x in cl + ' ' + pi for x in strong)

picked.sort(key=suspicious, reverse=True)
sample, seen_cl = [], set()
for o in picked:
    k = (o.get('CommandLine') or '')[:80]
    if k in seen_cl:
        continue
    seen_cl.add(k)
    sample.append(o)
    if len(sample) >= N:
        break

print('sampled', len(sample), 'process events')
envelopes = []
for i, o in enumerate(sample, 1):
    env = {'source': 'splunk', 'raw': {
        'search_name': 'BOTS Sysmon ProcessCreate',
        'sid': 'bots-harness-%04d' % i,
        'dest': o.get('Computer', 'unknown'),
        'user': (o.get('User') or 'unknown').split('\\')[-1],
        '_time': (o.get('UtcTime') or '').replace(' ', 'T') + 'Z',
        'ParentImage': o.get('ParentImage') or '',
        'CommandLine': o.get('CommandLine') or '',
        'Image': o.get('Image') or '',
        'Hashes': o.get('Hashes') or '',
        'TargetFilename': o.get('TargetFilename') or '',
    }}
    envelopes.append(env)
    json.dump(env, open('/tmp/bots_harness_%04d.json' % i, 'w'))
json.dump(envelopes, open('/tmp/bots_harness_all.json', 'w'))
print('envelopes written')
