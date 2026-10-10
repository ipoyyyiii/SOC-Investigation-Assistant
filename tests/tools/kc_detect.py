#!/usr/bin/env python3
"""Keycloak impossible-travel detector: pull events -> geo-enrich -> haversine -> POST to SOC webhook."""
import json, os, math, subprocess, time, urllib.request, datetime

KEY_HOST = 'ubuntu@13.212.120.162'
KEY = '/tmp/soc-install'
SOC = 'http://127.0.0.1:5678/webhook/soc-alert'
SOC_KEY = os.environ.get('SOC_KEY', 'REPLACE_WITH_ENV')
WINDOW_MIN, MAX_KMH = 60, 900

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout

def kc_events():
    """read Keycloak events via admin REST, over SSH to the Wazuh host"""
    out = sh("ssh -i %s -o ConnectTimeout=10 -o StrictHostKeyChecking=no %s 'bash /tmp/kc_events.sh'" % (KEY, KEY_HOST))
    try:
        return json.loads(out)
    except Exception:
        print('event fetch failed:', out[:200])
        return []

def geo(ip):
    try:
        with urllib.request.urlopen('http://ip-api.com/json/%s?fields=status,country,countryCode,city,lat,lon' % ip, timeout=15) as r:
            d = json.loads(r.read())
        if d.get('status') != 'success':
            return None
        return {'country': d['country'], 'cc': d['countryCode'], 'city': d['city'], 'lat': d['lat'], 'lon': d['lon']}
    except Exception:
        return None

def haversine(a, b):
    R = 6371.0088
    p1, p2 = math.radians(a['lat']), math.radians(b['lat'])
    dp, dl = p2 - p1, math.radians(b['lon'] - a['lon'])
    return 2 * R * math.asin(math.sqrt(math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2))

def main():
    events = kc_events()
    events = [e for e in events if e.get('type') in ('LOGIN', 'LOGIN_ERROR')]
    events.sort(key=lambda e: e.get('time', 0))
    print('events:', len(events))
    by_user, findings = {}, []
    for e in events:
        user = (e.get('details') or {}).get('username') or e.get('userId')
        ip = e.get('ipAddress')
        g = geo(ip)
        prev = by_user.get(user)
        it = None
        if g and prev and prev['geo'] and (e['time'] - prev['time']) / 60000 <= WINDOW_MIN:
            km = haversine(prev['geo'], g)
            hrs = (e['time'] - prev['time']) / 3600000
            kmh = km / hrs if hrs > 0 else 99999
            if kmh > MAX_KMH:
                it = {'flagged': True, 'km': round(km, 1), 'kmh': round(kmh), 'minutes': round((e['time'] - prev['time'])/60000, 2),
                      'from_ip': prev['ip'], 'from_cc': prev['geo']['cc'], 'from_city': prev['geo']['city'],
                      'to_ip': ip, 'to_cc': g['cc'], 'to_city': g['city'], 'max_possible_kmh': MAX_KMH}
                findings.append((user, it))
        by_user[user] = {'time': e['time'], 'ip': ip, 'geo': g}
        if e['type'] == 'LOGIN' and it:
            payload = {'source': 'keycloak', 'raw': {
                'event': 'LOGIN', 'user': user, 'user_id': e.get('userId'), 'realm': e.get('realmId'),
                'client_id': e.get('clientId'), 'ip': ip,
                'timestamp': datetime.datetime.utcfromtimestamp(e['time']/1000).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'time_ms': e['time'], 'error': None, 'geo': g, 'geo_source': 'ip-api.com',
                'impossible_travel': it,
                'mfa': {'note': 'login from new geo within %s minutes' % it['minutes']}
            }}
            body = json.dumps(payload).encode()
            req = urllib.request.Request(SOC, data=body,
                headers={'Content-Type': 'application/json', 'X-SOC-Key': SOC_KEY, 'X-SOC-TS': str(int(time.time()))})
            with urllib.request.urlopen(req, timeout=30) as r:
                print('posted impossible-travel for', user, r.status)
    if not findings:
        print('no impossible-travel detected in window')

if __name__ == '__main__':
    main()
