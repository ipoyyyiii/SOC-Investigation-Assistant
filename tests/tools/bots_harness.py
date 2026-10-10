#!/usr/bin/env python3
"""BOTS harness runner — fire envelopes, then score deterministically from DB results."""
import json, os, subprocess, time, urllib.request, sys

KEY = os.environ.get('SOC_KEY', 'REPLACE_WITH_ENV')
def psql(q):
    r = subprocess.run(['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'n8n', '-d', 'soc', '-t', '-A', '-c', q],
                       cwd='/opt/soc-n8n', capture_output=True, text=True)
    return r.stdout.strip()

envs = json.load(open('/tmp/bots_harness_all.json'))
print('firing', len(envs), 'envelopes in 2 batches')

TS = str(int(time.time()))
for i, env in enumerate(envs, 1):
    body = json.dumps(env).encode()
    req = urllib.request.Request('http://127.0.0.1:5678/webhook/soc-alert', data=body,
        headers={'Content-Type': 'application/json', 'X-SOC-Key': KEY, 'X-SOC-TS': str(int(time.time()))})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(i, r.status)
    except Exception as e:
        print(i, 'ERR', e)
    if i == 5:
        time.sleep(60)

print('waiting for AI chains (240s)...')
time.sleep(240)

sids = [e['raw']['sid'] for e in envs]
rows = {}
for s in sids:
    q = ("SELECT incident_id || '|' || COALESCE(raw::jsonb->>'attack_type','') || '|' || "
         "COALESCE(raw::jsonb->'observables'->>'parent_image','') || '|' || "
         "COALESCE(raw::jsonb->'observables'->>'command','') || '|' || "
         "COALESCE(raw::jsonb->'observables'->>'hash','') "
         "FROM soc_events WHERE raw::text LIKE '%" + s + "%' LIMIT 1")
    out = psql(q)
    rows[s] = out.split('|') if out else []

score = {'stored': 0, 'attack_type_process': 0, 'parent_preserved': 0, 'command_preserved': 0, 'hash_present': 0}
for s in sids:
    r = rows[s]
    if len(r) >= 1 and r[0]:
        score['stored'] += 1
        if len(r) >= 2 and r[1] == 'process':
            score['attack_type_process'] += 1
        if len(r) >= 3 and r[2]:
            score['parent_preserved'] += 1
        if len(r) >= 4 and r[3]:
            score['command_preserved'] += 1
        if len(r) >= 5 and r[4]:
            score['hash_present'] += 1

# incident + risk produced?
inc = psql("SELECT count(*) FROM incidents WHERE incident_id IN (SELECT incident_id FROM soc_events WHERE raw::text LIKE '%bots-harness-%');")
ti = psql("SELECT count(DISTINCT indicator) FROM ti_cache WHERE indicator LIKE '%DB06C3%' OR indicator LIKE '%osk%';")
flagged_not_stored = [s for s in sids if not (len(rows[s]) >= 1 and rows[s][0])]

n = len(sids)
lines = []
lines.append('# BOTS harness score (2026-10-09)\n')
lines.append('Dataset: BOTS v1 attack-only (Splunk/Sysmon export, real attack sequence: osk.exe -> iexplore/wmic/vssadmin/schtasks/powershell)')
lines.append('Sample: %d Sysmon ProcessCreate events replayed through /webhook/soc-alert (source=splunk)\n' % n)
lines.append('| Criterion | Score |')
lines.append('|---|---|')
lines.append('| Events stored as incidents | %d/%d |' % (score['stored'], n))
lines.append('| attack_type = process (router) | %d/%d |' % (score['attack_type_process'], n))
lines.append('| parent_image preserved | %d/%d |' % (score['parent_preserved'], n))
lines.append('| command preserved | %d/%d |' % (score['command_preserved'], n))
lines.append('| hash (SHA256) preserved | %d/%d |' % (score['hash_present'], n))
lines.append('| Incidents rows created | %s |' % (inc or '0'))
lines.append('| TI cache rows for BOTS indicators | %s |' % (ti or '0'))
if flagged_not_stored:
    lines.append('\nNOT STORED: ' + ', '.join(flagged_not_stored))
lines.append('\nPer-event:')
for s in sids:
    lines.append('- %s: %s' % (s, 'OK ' + '|'.join(rows[s][:5]) if (len(rows[s]) >= 1 and rows[s][0]) else 'MISSING'))
open('/home/ubuntu/socautomation/tests/bots-score.md', 'w').write('\n'.join(lines) + '\n')
print('\n'.join(lines[:12]))
print('written -> tests/bots-score.md')
