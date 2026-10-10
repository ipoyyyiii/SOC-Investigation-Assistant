#!/usr/bin/env python3
"""suricata-bridge — tail suricata eve.json, flatten alert events into a Wazuh-friendly log line."""
import json, time, os, sys

EVE = '/var/log/suricata/eve.json'
OUT = '/var/log/suricata/soc-alerts.log'

def flatten(d, prefix=''):
    out = {}
    for k, v in d.items():
        key = prefix + k
        if isinstance(v, dict):
            out.update(flatten(v, key + '.'))
        elif isinstance(v, list):
            out[key] = json.dumps(v)[:120]
        else:
            out[key] = v
    return out

def emit(d):
    f = flatten(d)
    line = ('SOC-SURICATA %s signature="%s" sid=%s severity=%s src_ip=%s dst_ip=%s proto=%s method=%s url=%s'
            % (d.get('timestamp'), (f.get('alert.signature') or '').replace('"', ''),
               f.get('alert.signature_id'), f.get('alert.severity'), f.get('src_ip'), f.get('dest_ip'),
               f.get('proto'), f.get('http.http_method'), (f.get('http.url') or '')[:120]))
    with open(OUT, 'a') as fh:
        fh.write(line + '\n')

def main():
    while not os.path.exists(EVE):
        time.sleep(2)
    with open(EVE) as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get('event_type') != 'alert':
                continue
            sev = (d.get('alert') or {}).get('severity')
            if sev is None or sev > 3:
                continue
            emit(d)

if __name__ == '__main__':
    main()
