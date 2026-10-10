#!/usr/bin/env python3
"""soc-cloudtrail — poll AWS CloudTrail management events -> POST to SOC webhook."""
import json, os, os, subprocess, time, urllib.request

KEY = os.environ.get('SOC_KEY', 'REPLACE_WITH_ENV')
SOC = 'http://127.0.0.1:5678/webhook/soc-alert'
CREDS = '/root/aws-creds'
STATE = '/var/lib/soc-cloudtrail-seen.json'
MAX_PER_RUN = 40

def run_aws(start):
    cmd = ['aws', 'cloudtrail', 'lookup-events', '--max-results', str(MAX_PER_RUN),
           '--region', 'ap-southeast-1']
    if start:
        cmd += ['--start-time', start]
    env = dict(os.environ, AWS_SHARED_CREDENTIALS_FILE=CREDS)
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0:
        print('aws-err:', r.stderr[:200])
        return []
    try:
        return json.loads(r.stdout).get('Events', [])
    except Exception as e:
        print('parse-err:', e)
        return []

def load_seen():
    try:
        return set(json.load(open(STATE)))
    except Exception:
        return set()

def save_seen(s):
    if len(s) > 2000:
        s = set(list(s)[-500:])
    json.dump(list(s), open(STATE, 'w'))

def flatten(ev):
    try:
        detail = json.loads(ev.get('CloudTrailEvent') or '{}')
    except Exception:
        detail = {}
    return {
        'event_id': ev.get('EventId'),
        'event_name': ev.get('EventName'),
        'event_time': ev.get('EventTime'),
        'username': ev.get('Username') or detail.get('userIdentity', {}).get('userName') or 'unknown',
        'source_ip': ev.get('sourceIP') or detail.get('sourceIPAddress') or '',
        'user_agent': detail.get('userAgent', ''),
        'aws_region': detail.get('awsRegion', ''),
        'mfa': str(detail.get('userIdentity', {}).get('sessionContext', {}).get('attributes', {}).get('mfaAuthenticated', '')),
        'access_key_id': (detail.get('userIdentity', {}) or {}).get('accessKeyId', ''),
        'read_only': ev.get('ReadOnly', ''),
        'error_code': detail.get('errorCode', ''),
        'event_source': ev.get('EventSource', ''),
    }

def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    seen = load_seen()
    events = run_aws(None)
    events.sort(key=lambda e: e.get('EventTime', ''))
    new = [e for e in events if e.get('EventId') not in seen]
    posted = 0
    for e in new[-MAX_PER_RUN:]:
        r = flatten(e)
        if not r['event_name']:
            continue
        env = {'source': 'cloudtrail', 'raw': r}
        body = json.dumps(env).encode()
        req = urllib.request.Request(SOC, data=body, headers={
            'Content-Type': 'application/json', 'X-SOC-Key': KEY, 'X-SOC-TS': str(int(time.time()))})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                posted += 1
        except Exception as ex:
            print('post-err:', ex)
        seen.add(r['event_id'])
    save_seen(seen)
    print('events:', len(events), 'new:', len(new), 'posted:', posted)

if __name__ == '__main__':
    main()
