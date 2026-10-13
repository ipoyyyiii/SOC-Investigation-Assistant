# Test log Phase 1-4 (2026-10-06)
Webhook: POST /webhook/soc-alert, workflow 01_SOC_Alert_Intake (16 nodes).

| ID | Case | Expected | Result |
|----|------|----------|--------|
| T1 | fresh IP failed_login | new incident + Discord | OK (INC-...4551, parent NULL) |
| T2 | same key failed | duplicate, parent set, NO Discord | OK (...2656 parent ...4551) |
| T3 | same key success_login | breakthrough: new incident, no parent | OK (...9376, parent NULL) |
| T4 | diff IP same host/user | new incident, related>=1 to AI | OK (...4106 stored, success) |
Executions: all `success`. TI: VT + AbuseIPDB live, UNKNOWN-safe. AI: Nemotron free, 503 sometimes -> facts-only fallback.
Pending human check: Discord msgs (T3 flag auth_success_after_failures, T4 related counts, TI lines on AI-fail).

## Human Discord check (2026-10-06) — PASS
- T1 (...4551): related 185.220.101.5 (8-min window), TI "clean" narrated. OK.
- T3 (...9376 breakthrough): "Successful SSH login as root after 3 failed within 12-min", counts block + TI embedded + compromise flags. OK.
- T4 (...4106): 5 events / 3 IPs / success flagged, TI lines present. OK.
Cosmetic: AI sometimes returns objects (not arrays) in OBSERVED/INFERRED -> raw JSON blob. Fix in Phase 6 prompt (force arrays).

## Phase 5-6 (2026-10-06) — PASS
- Timeline ASC + FIRST/SUCCESS/LATEST live in success AND fallback paths.
- Fallback TI line fixed (reads TIMerge).
- AI chain: primary Nemotron + Gemma/Lightning fallbacks (clean-evidence ref) + facts-only last resort.
- Own goal found+fixed: unescaped quotes in guard broke ALL AI calls ("invalid syntax") — validated offline with node eval now.
- Phase 6 proof (...2391): MITRE T1110.003 with evidence reason + confidence 0.88 + 2-IP correlation narrated.

## Phase 7-9 (2026-10-06) — PASS
- Gmail SMTP (app password) + Discord parallel, identical content.
- Deterministic EVIDENCE block in success path.
- CaseStore: incident row + IOC, duplicates bump event_count (tested event_count=2).
- 02_SOC_Decision: webhook /soc-decision validates TP|FP|ESCALATE, rejects garbage, clean OK response.

## Phase 7-10 (2026-10-06) — PASS
- Gmail SMTP parallel with Discord, identical content.
- EVIDENCE deterministic block in success path (counts/TI/risk).
- CaseStore: incidents + iocs, Counter bumps event_count.
- 02_SOC_Decision: TP/FP/ESCALATE validated, clean OK.
- ResponseGate: risk 31 LOW (fail only) vs 71 MEDIUM + PROPOSED block (success), propose-only, MITRE T1021.004/T1078.
- Remaining micro: log PROPOSED rows to incident_actions (ResponseLog node); TI cache; full-report page; Wazuh real (2b); expansion (11).

## Phase 8-10 refresh (2026-10-06)
- ResponseLog: PROPOSED rows written (verified 2 rows with gate snapshots).
- Cross-window proof: fail ...7079 escalated via prior success ...7473 still in 15-min window (correct behavior, not a bug).
- Concurrency note: webhook executions overlap (71 ran 19:25:33-19:27:10, 72 started 19:27:04) — gate snapshots are per-execution from Correlate-time rows; no cross-talk observed.

## Phase 11 (2026-10-07) — PASS (SSH/PowerShell/hash/phishing)
- PowerShell: T1059.001+T1027.010, parent+command, own playbook. OK.
- Hash: cross-type correlation (2255 exec -> 3257 detect), EICAR VT 65 mal. OK.
- Phishing: T1566.002/T1566.21/T1036.004, sender/auth/URL verdicts, own playbook. OK.
- Bug archaeology: (a) EICAR hash 58char -> recomputed 64char locally (MD5-verified); (b) Format read ti[0] only -> loop all; (c) TIMerge $input shifted after TI_URL insert -> explicit $('TI_VTFile') ref. Root causes, all fixed+verified.
- TODO: regenerate VT API key (exposed in chat); TI cache (quota); Win 4625; C2/webshell/lateral types; full-report page.

## TI cache (backlog #1) — PASS MISS+HIT
- MISS (34.34.34.34): 2 rows written (virustotal_ip+abuseipdb).
- HIT (same IP, new incident): 0 new API calls (fetched_at unchanged), verdict still served.
- Bug archaeology: (a) IF polarity inverted; (b) string `equal` unreliable -> number compare; (c) bash ate `$()` in inline python (use files); (d) missing `=` expression prefix (literal string always non-empty -> always skip); (e) 0-row query kills chain -> alwaysOutputData+pivot collapse; (f) isEmpty('') is false, only null/undefined is empty.

## Backlog #2 Win logon (2026-10-07) — PASS
- 4625 fail -> 4624 success breakthrough, flag YES, risk 71 + PROPOSED, T1078/T1110, DC/lateral playbook. Zero downstream changes (proves generic pipeline).

## Full-report page — PASS
- 03_SOC_Report (GET /soc-report?incident_id=): incident + events + IOCs + decision in HTML. Verified INC-20261006-9938 (TP).
- Lesson: manual DB workflow creation needs shared_workflow ownership + UI publish for outbox lifecycle; raw pointer updates leave outbox FAILED.

## Full loop closed (2026-10-07)
- Notification carries `Full report: /webhook/soc-report?incident_id=` (relative URL works on tunnel + future HTTPS).
- Verified VT 1-malicious IP flows into risk + narrative.
- SCOREBOARD: 11.5/12 phases. Remaining: C2/webshell/lateral (needs NetFlow/DNS sources), Wazuh real (needs host), VT key rotation (user action).

## Real-detection E2E (2026-10-07, Wazuh 4.14.8 + agent 001)
- SSH brute real (127.0.0.1 x10) -> 5763 L10 -> dedup parent/child -> Discord with real host/user. PASS.
- ClamAV real (EICAR) -> custom rule 100010 + decoder sha256 extraction -> VT 66 mal -> Discord. PASS.
- Bug archaeology (real env): TCP-only manager (no UDP listener) -> agent protocol=tcp; rule-id collision 87105 (VT ruleset owns it) -> local range 100010; case-insensitive <match>FOUND</match> fired on SSM logs -> locked with <decoded_as>; agent default has no auth.log monitor; mock-default IPs polluted real alerts -> neutralized to ''.

## 7 fixes #1-5 — PASS
- #1 webhook auth: 403 anon/wrong, real key flows (real 5763 incidents).
- #2 decision auth: 403 anon, OK+state change with key; BOGUS rejected.
- #3 risk stored + ORDER BY risk_score works (33 LOW newest).
- #4 breakthrough linkage same-IP parent (2853->2097).
- #5 related TI from cache (41.x verdict served to 42.x with 0 new API calls).

## 7 fixes — ALL PASS (2026-10-07)
- #1 webhook auth: 403 anon/wrong, real key flows (real 5763 incidents).
- #2 decision auth: 403 anon, OK+state change with key; BOGUS rejected.
- #3 risk stored + ORDER BY (33 LOW; old rows NULLS LAST).
- #4 linkage same-IP parent (2853->2097; cross-IP fallback to oldest).
- #5 related TI from cache, 0 new API calls.
- #6 anchored window: replay 09:16 alert correlated 09:15 cluster (was impossible with NOW()).
- #7 severity stored (CRITICAL L12) + docs/LIMITATIONS.md (10 items).
- Bug: Correlate 0-row silent stop (same class as DedupCheck/TICacheRead) -> alwaysOutputData audit; INSERT nodes reliably emit, left as-is.

## 7 fixes + split — ALL DONE (2026-10-07, subagents)
- Auth webhook+decision, analyst identity+audit, report token, replay guard; all 403s verified.
- Split: 04_SOC_Enrichment (20) + 05_SOC_AIAnalysis (7), orchestrator 20 nodes; full-path positive = 3x success.

## Sisa-bersih — PASS
- Idempotency: identical POST x2 -> 1 row, 2x success, no dup incident/notify (idem_key + ON CONFLICT).
- Retro links: replay/old-IP alert links 24h history (7504 -> 7796), deterministic line + AI narration.

## Sisa-bersih final — ALL PASS
- Idempotency (idem_key + ON CONFLICT): identical POST x2 -> 1 row.
- Retro links 24h same-IP + deterministic line + AI narration.
- Per-analyst tokens: no-token 403, spoof body bob recorded alice-lead, revoked bob 403, restored.

## Reliability (subagent, 2026-10-07) — DONE
- TI timeouts 30s->20s (AI untouched 60s).
- 06_SOC_DLQ (ErrorTrigger -> failed_jobs) wired to 01/02/03 via settings.errorWorkflow.
- Live DLQ test pending human (pin payload / force failure in UI).

## FP case study: grub/shim unattended update (2026-10-07)
- 5x FIM 550 on /boot/efi/* (22:59:44) from unattended-upgrades installing grub-efi/shim-signed (verified apt history).
- Pipeline: detected + VT-checked (0 mal) + AI gave balanced low-confidence analysis pointing at package-manager check.
- Dedup race note: 5 simultaneous alerts -> 5 incidents (concurrent same-key race, accepted limitation, documented).
- Analyst verdict: all 5 -> FP with note (via decision endpoint, alice-lead). Full TP/FP loop demonstrated on REAL data.

## BOTS-2016 root cause (2026-10-08) — FOUND (own goal)
- Symptom: 2016-timestamp runs died silently/fast; `=NNN` integer errors + ti_cache dups in logs.
- Actual causes, in order: (1) MY ts-semantics edit ate `}}',` after incident_id -> mustache "invalid syntax" at StoreEvent (all post-edit runs failed there); fixed + verified. (2) ti_cache dup race on concurrent runs -> ON CONFLICT guards. (3) `=NNN` = DLQ LogFailedJob failing on the PRIMARY error (secondary cascade, fixed via Code-sanitize rewrite).
- 2016 dates were NEVER the problem. Lesson: diff SQL edits before/after + verify published (not just draft).
- BOTS sid7 (2016): full 85s success, incident stored. Awaiting Discord content check.
- BOTS sid7 Discord VERIFIED: parent masquerading analysis, cmd hash TI 0-mal (correct, benign hash), T1036.003+T1059.003 evidence-tied, process playbook. Multi-SIEM claim PROVEN with real Splunk-native data.

## Web/webshell coverage — LIVE (2026-10-08)
- Lab: nginx+php-fpm on Wazuh host (SG port 80 opened by user), /var/www/html/upload.php (intentional vuln), webshell sh.php exec verified (uid=33 www-data).
- Wazuh: localfile apache access.log + syscheck realtime on /var/www/html/uploads. Custom rule 100011 level 10 (if_sid 31100 + match cmd=) MITRE T1505.003.
- Debug journey: rule initially dead because web-accesslog decoder SUCCESS swallows bare <match> rules; fixed by anchoring under 31100. <field name=url> rejected by analysisd ("url is static") -> use if_sid+match.
- Side incident: /var/ossec/etc got wiped when apt removed wazuh-agent (package conflict with wazuh-manager); rebuilt ossec.conf integration+localfile+syscheck, custom rule/decoder, restored soc-webhook.key. Manager active.
- E2E: sh.php?cmd=hostname -> alert 100011 -> custom-n8n -> INC-20261008-4409 (level 10, src_ip <N8N-VPS>) -> execs 359/360/361 all success.

## TI URL path + error-poison fix (2026-10-08/09) — LIVE
- Test1: real URLhaus URL http://123.9.84.231:39954/i -> VT 404 (URL not in VT DB) AND the error got CACHED into ti_cache (poison) — bug found by testing.
- Bug2 found same run: abuseipdb cached JS error "Cannot read properties of undefined" — 21 poisoned rows total, all deleted.
- Fix: W_VTIP/W_Abuse/W_File/W_Url guarded with AND '{{ $json.error ? 1 : 0 }}' = '0' (workflow 04 republished 1db665c3).
- Test2 (after fix): OpenPhish URL https://usps-email.com/ -> VT URL verdict REAL: 46 harmless / 19 MALICIOUS / 1 susp / 28 undetected. URL branch now proven live.
- Extra finding: chat-pasted VT key is DEAD (401) — user rotated it earlier; n8n credential already holds the new key (pipeline VT calls still working). Rotation action in cleanup list can be marked DONE for VT.

## TI cache error-poison + URL TI live (2026-10-08/09) — FIXED + PASS
- Bugs found by live-testing URL branch: (1) VT 404 "URL not found" got WRITTEN into ti_cache (poisoned future lookups); (2) abuseipdb JS error cached the same way — 21 poisoned rows total, all deleted.
- Real finding: chat-shared VT API key is DEAD (401 everywhere). n8n credential already holds the ROTATED key (pipeline VT still working) — user rotated earlier. VT rotation = DONE (mark cleanup).
- Guard fix: W_VTIP/W_Abuse/W_File/W_Url now skip error results (workflow 04 republished 1db665c3).
- Proof: OpenPhish URL https://usps-email.com/ -> VT URL verdict REAL 46 harmless / 19 MALICIOUS / 1 susp / 28 undetected -> INC-20261008-2188 risk 56 MEDIUM.

## Scanner ASN auto-close (2026-10-09) — LIVE E2E
- Data: DB-IP asn-lite 2026-10 (CC-BY) 477,362 ranges -> soc.ip_asn_cache (Postgres, inet range + index).
- Seed list scanner_asn (8 ASN: DigitalOcean/Vultr/OVH/Linode/Hetzner/Contabo/ColoCrossing/Tencent — hosting heuristic, documented assumption).
- 07_SOC_AutoClose: DB-created cron workflow; n8n [this build] durable scheduler INACTIVE on this instance -> scheduleTrigger never fired (debug-log proven). Rebuilt as webhook + host cron */5 curl (localhost-only, X-SOC-Key gated, wrong key -> exec error).
- DB-only workflow creation needs shared_workflow row (ownership) AND webhook_entity row for trigger registration — both added (lesson recorded; explains old report-page failure mode).
- E2E: DO IP 24.144.68.5 brute alert -> INC-20261008-8584 -> cron -> status CLOSED_FP, analyst_decisions row (analyst=asn-autoclose). Second incident also closed idempotently. Manual SQL run verified identical logic.

## PowerShell obfuscation scorer + SQL-injection-class bug (2026-10-09) — FIXED + LIVE
- Live-testing found SQL break when CommandLine contains single quotes: `DownloadString('http...` -> mustache JSON broke soc_events insert (error near token).
- Root cause chain: n8n expression engine does NOT support .replace(/'/g, "''") (regex literal) in SQL templates -> mangle; and plain JSON.stringify leaves ' unescaped.
- Fix: NormalizeAlert computes raw_b64 (real JS Buffer in Code node); StoreEvent/StoreDuplicate use convert_from(decode('{{..raw_b64}}','base64'),'UTF8')::jsonb. Template-safe by construction (b64 charset only).
- Obfuscation scorer (deterministic, no AI) in NormalizeAlert.wazuh/powershell branch: patterns (encoded, IEX, download cradle, hidden, AMSI bypass, caret, COM) + long-b64; allowlist (admin script paths) downgrades. Live proof:
  - cradle `powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('...')` -> obf_score 3, reasons [invoke-expression, download cradle, hidden], command stored intact, execs success (INC-20261008-4240).
  - allowlisted `powershell -File C:\Scripts\backup.ps1` -> obf_score 0 reason "allowlisted admin script".
- FormatNotification EVIDENCE now shows "Obfuscation: X/10 (reasons)" (Discord verification pending by human).

## Phishing blast-radius LAB SIM (2026-10-09) — LIVE
- Mailpit (docker, n8n VPS, SMTP 1025+API 8025) = lab inbox. Email phish terkirim via smtplib, inbox verified via API (1 msg).
- Victim click link -> GET /phish/track?u=jdoe&c=40291 ke nginx Wazuh -> access.log -> custom rule 100012 level 10 (if_sid 31100 + match phish/track, MITRE T1566.002) -> alert -> INC-20261008-8665 E2E (execs 404/405 success).
- Scope note: LAB-SIMULATED (no real internet inbox); delivery+click+detect loop beneran terjadi. Config Wazuh rules/decoder disalin ke repo config/wazuh/.

## Green-tail sweep 2 (2026-10-09): risk weight + web branch + process chain
- Web branch normalizer FIXED+depployed: attack_type web / outcome suspicious_request / observables.url (was falling to ssh-auth -> AI hallucinated "failed SSH login"). Live proof INC-7358.
- Risk v2: 10 + level*2 + 15 (web class, DBIR #1 vector) + 5 (public src) + 10 (obf>=3) + TI + 40 (success-after-fail). Cross-node refs ($('NormalizeAlert')) immune to merge shape. Live: webshell 35 LOW -> 50 MEDIUM.
- Process chain render in report page (Process chain table ts/parent_image/command/hash) + QEvents now returns raw jsonb. Live proof INC-8061: osk.exe -> /d /c taskkill -> DB06C35... Bug caught: '+ ptree +  +' unary-plus NaN -> fixed.
- Reliability gap found: n8n-tunnel systemd was inactive (bridge down during a restart window); alerts in that window are LOST (integration is fire-and-forget, no retry). Noted for LIMITATIONS.

## DVWA full web-exploit coverage — LIVE E2E (2026-10-09)
- Lab: docker.io + DVWA (citizenstig) + MariaDB on Wazuh host (dvwa:8080 local-only), proxied via nginx `location ^~ /dvwa/` -> access.log monitored by Wazuh (lesson: regex `~ \.php$` prefix location must be `^~`; POST bodies NOT logged -> POST-based cmd-injection invisible to log rules, documented gap).
- Exploit proven (python urllib session driver /tmp/dvwa_drive2.py on host): security=low, SQLi `1' OR '1'='1` -> dump users (admin/Gordon/Hack), LFI ../../../../etc/passwd -> leaked, CMDi `127.0.0.1;cat /etc/passwd` -> executed.
- Wazuh custom rules 100013 SQLi / 100014 LFI / 100015 CMDi (if_sid 31100 anchor, T1190). URL-encoding mattered: urllib sends %20OR%20 not '+OR+' -> rule patterns updated.
- E2E: VPS replay -> INC-20261009-8316 (SQLi, src <N8N-VPS>, risk 50 MEDIUM, url observable captured) + localhost runs INC-2810/7191.

## URLhaus + OTX TI sources — LIVE (2026-10-09)
- Credentials via user (n8n UI): TI-URLhaus-auth, TI-OTX-auth (httpHeaderAuth).
- Bugs found on the way (all root-caused, all fixed):
  1. URLhaus header must be exactly `Auth-Key` (was X-Auth-Key) -> credential rebuilt via n8n CLI import (decrypted export -> fix header -> single-entry import; temp files shredded).
  2. abuse.ch main host now bot-gates with verify-ua 307 -> use https://urlhaus-api.abuse.ch/v1/url/ (works clean).
  3. HTTP node defaulted to GET -> URLhaus 405 http_post_expected -> explicit "method": "POST".
  4. HTTP nodes with onError=continueRegularOutput REPLACE the flow item with {error} -> downstream lost rule_level -> RestoreItem nodes after error-prone calls.
  5. Parallel branch from EnrichmentTrigger made the sub-workflow return the Postgres write result (not the alert item) -> linearize: URLhaus first in chain.
  6. Parallel output from trigger node doesn't fan out reliably; chain edge W_VTIP->IF_CAbuse was accidentally dropped in an earlier patch -> canonical chain restored end-to-end.
- LIVE PROOF (INC-20261009-2098, risk 60 MEDIUM, up from 35):
  - OTX: IP 45.148.10.88 -> 29 pulses (+10 risk)
  - URLhaus: http://123.9.84.231:39954/i -> url_status online / threat malware_download / payload ELF (+15 risk)
  - VT ip 5 mal + URL 3 mal still served from cache path.
- CaseStore 'column undefined' crash (rule_level lost via error-item) resolved by chain restore; watch-item: FormatNotification/CaseStore still use template .replace() patterns -> TODO b64.

## C2 beaconing via Suricata — LIVE E2E (2026-10-09)
- Suricata 7.0.3 on Wazuh host (enp39s0, note: default eth0 wrong), ET/open rules + custom soc-lab.rules (sid 1000001 C2 beacon pattern on /dvwa/beacon, sid 1000002 DNS).
- eve.json (alert+http+dns+tls). Bridge: /usr/local/bin/suricata-bridge.py (systemd) tails eve.json, flatten alert events -> /var/log/suricata/soc-alerts.log (SOC-SURICATA ...) -> Wazuh localfile syslog + decoder suricata-bridge (srcip/dstip/proto/method/url) + rule 100016 (T1071 Application Layer Protocol).
- Wazuh json decoder CANNOT read eve.json ("Too many fields for JSON decoder") -> flatten-bridge pattern (same as custom-n8n integration).
- E2E: curl /dvwa/beacon from VPS -> suricata alert -> wazuh 100016 -> n8n -> INC-20261009-6709 (src_ip <N8N-VPS>, risk 35) + INC-2909 earlier. logtest+live both verified.
- GAP noted: normalizer still routes suricata alerts via fallback (no attack_type/network branch, rule.mitre not propagated) -> risk 35 LOW (acceptable, backlog item).
- DNS-exfil live demo: NOT done (resolver topology; DNS logging + rule ready).

## Keycloak impossible-travel — LIVE E2E (2026-10-09)
- Keycloak 26.8.0 (docker, Wazuh host :8081 local-only, /opt/kc-data chown 1000 — CRASH ROOT CAUSE was volume perms). KC_PROXY_HEADERS=xforwarded so X-Forwarded-For lands in event ipAddress. Events: jboss-logging LOGIN/LOGIN_ERROR. User setup gotcha: user needs email set (else "Account is not fully set up" / resolve_required_actions).
- Lab events: login A 8.8.8.8 (US) 18:29:35 -> login B 1.1.1.1 (AU) 18:29:38 (3s!) + LOGIN_ERROR from 200.160.2.3 (BR).
- Detector tests/tools/kc_detect.py (VPS): reads events via SSH+kc_events.sh -> geo via ip-api.com -> haversine >900km/h <=60min -> POST source=keycloak.
- E2E: INC-20261009-1615 rule_id keycloak-impossible-travel, risk 79 HIGH, src 1.1.1.1. Normalizer branch 'identity' + ResponseGate +40 for impossible_travel.
- LIMITATIONS: lab-simulated (spoofed XFF, not real geo-separated clients); Entra-ID real impossible travel still P1/P2 paid.

## Windows lab (AWS c7i.flex-large, Server 2022, <WIN-LAB>) — LIVE (2026-10-09/10)
- Access: RDP from Mac (Windows App) for bootstrap; remote via WinRM 5985 (socadmin) from VPS for all automation. SG: Wazuh host needs inbound 1514/1515 from VM IP (agent calls OUT).
- Wazuh agent 002 win-lab-01 enrolled to manager <WAZUH-HOST> + Sysmon64 (SwiftOnSecurity config) via WinRM. Auditpol failure-audit enabled.
- Custom rules (if_sid chains matter — root rules lose to ruleset parents): 100021 (4625 T1110), 100022 (child of 60106, 4624 T1078), 100023 (if_group sysmon_event1 + commandLine pcre2, T1059.001), 100024 (if_sid 61138, 7045 T1543.003).
- ATTACKS REAL + E2E: 6x failed logon (LogonUser wrong pass) -> 100021 -> INC-8377; success logon after failures -> 100022 -> INC-5842; PowerShell DownloadString cradle -> Sysmon EID1 -> 100023 -> INC-7919 (risk 45 MEDIUM); sc.exe create service -> 7045 -> 100024.
- NOT DONE: AD DS forest promotion (Install-WindowsFeature success=False on this box; dcpromo.log empty) -> kerberoast/AS-REP/NTDS.dit rows remain untested. Lateral is same-host (PsExec pattern via sc.exe).
- Costs: c7i.flex-large Windows ~$0.12/h + 40GB EBS; stop when idle.

## Windows AD attack chain — LIVE (2026-10-10)
- AD DS promoted: forest corp.lab / CORP on DC01 (Install-WindowsFeature AD-Domain-Services+DNS — earlier failure was the invalid feature name "DNS-Server-Full-Site"; correct = DNS).
- Targets: svc_lab (SPN HTTP/labweb), asrep_lab (no-preauth).
- ATTACKS -> E2E incidents (all via win-lab-01):
  1. Kerberoast: Rubeus kerberoast -> 4769 TicketOptions 0x40810000 x6 -> rule 100026 (T1558.003) -> INC-20261010-1903
  2. NTDS.dit attempt: vssadmin create shadow + copy -> rule 100028 (T1003.003, via sysmon_event1 commandLine pcre2) -> INC-20261010-9472
  3. (earlier) 4625 x6 -> 100021 T1110 -> INC-8377 | 4624 success -> 100022 T1078 -> INC-5842 | PS DownloadString cradle -> 100023 T1059.001 -> INC-7919/3924 (risk 45 MEDIUM) | sc.exe service -> 100024 T1543.003 -> INC-3693
- AS-REP roast (Rubeus asreproast) executed but RC4-0x17 rule didn't fire (AES used) — technique demonstrated, rule 100027 kept for RC4 case.
- RULE LESSON (repeated): custom rules must chain to the rule that actually fires (60106->100022->100026; 61138->100024; sysmon_event1->100023/100028). Root rules lose to ruleset parents.

## A-list sweep (2026-10-10) — 3 dari 3 selesai
1. **DNS exfil live**: suricata rules fixed (1000002 exfil + 1000003 high-entropy, direction any->53). Bridge service stale after suricata restart (file handle basi) -> restart suricata-bridge fixes. E2E: dig base64label.tunnel-exfil.test -> suricata -> wazuh 100017 T1048.003 + 100018 T1071.004 -> INC-20261010-7107. (INC-6568 also.)
2. **Gmail re-check**: GmailNotify executed + "finished successfully" in execution logs post-split (no SMTP errors in 45m).
3. **CaseStore apostrophe landmine fixed**: notification_text + threat_intel now stored via base64 (FormatNotification.notification_b64 + ResponseGate.ti_b64 + convert_from(decode(...))). Verified: INC-20261010-8130 stored with quoted CommandLine intact, ti_summary NOT NULL. No more template .replace() pattern in workflow 01.

## AWS CloudTrail account-takeover — LIVE (2026-10-10)
- User created IAM read-only user soc-cloudtrail-ro; creds at /root/aws-creds (VPS). Poller /usr/local/bin/soc-cloudtrail.py (cron */5) -> lookup-events -> POST source=cloudtrail (dedupe via /var/lib/soc-cloudtrail-seen.json).
- Normalizer branch (source=cloudtrail): attack_type cloud-identity, sensitive-event rule_ids (+25), denied (+10), public-ip (+5).
- E2E: real account events -> incidents (root ConsoleLogin events from <analyst-home-IP> Safari/macOS MFA=true etc). DEMO: attacker with stolen read-only creds tried StopLogging (T1562.008) from <N8N-VPS> -> AccessDenied -> INC-20261010-7019 risk 75 HIGH. CreateAccessKey attempt also denied (event pending CloudTrail latency, cron will pick up).

## Notification presentation fixes (2026-10-10) — verified via cloudtrail playback
Bugs found from real Discord message (INC-8487): (1) hardcoded "Wazuh rule" label; (2) SSH playbook for cloud events; (3) TI hostname lookup shown as ipv4; (4) EVIDENCE block missing in AI-fallback path; (5) missing space in label.
Fixes: source-aware label map (wazuh/splunk/email/keycloak/cloudtrail/suricata), playbooks per attack_type (cloud-identity/identity/web/process/persistence/win-logon), skip non-IP TI in OBSERVED + EVIDENCE, EVIDENCE block in fallback, observables.access_key added.
Proof: INC-20261010-6994/7800/1506 — "AWS CloudTrail event cloudtrail-stoplogging" + cloud playbook + no hostname TI + evidence block + facts-only. Risks: CreateAccessKey denied -> 100 HIGH; StopLogging -> 75 HIGH.
Pitfall logged: mustache-anchor ordering (fix3 anchors on text fix1 removes) + unclosed paren in injected IIFE (node --check caught both).

## Notification UX rework — LIVE (2026-10-12)
- Rewrote FormatNotification (English only): verdict-first, human labels, numbers with context, one template for success+fallback, smart truncate (link+NOTE never cut). AI observed/next-steps replaced by deterministic evidence/playbooks; AI summary kept; rule MITRE always shown.
- Proof: INC-20261012-2431 (SSH brute, 1593 chars) + INC-20261012-6543 (phish, 1676 chars) — both ≤1900, Discord delivered, link+NOTE intact, MITRE Rules T1110 / T1566+T1566.001. AI rate-limited → fallback path verified LIVE.
- Also fixed: GmailNotify text `=={{`→`={{`; pluralization; `mal`→`malicious`. Repo 01 synced (2 hunks), secret scan clean. Backup: /tmp/opencode/notify-rework/backup-01-20261012-222156.json. Offline samples: /tmp/opencode/notify-rework/samples.md.
- Left as-is: Gmail subject `=={{`; AI-success live path (offline only); Discord-client visual check (human). Pre-existing live-vs-repo divergence found (Correlate 15min vs 24h, StoreEvent NOW(), cloudtrail rejected live) — separate task, DLQ catching the fallout.

## Notify v2 — Discord card + HTML email (2026-10-13)
- Discord: plain card, no emoji, verdict-first, numbered actions, empty fields omitted, ≤1900. Gmail: HTML enterprise-style (severity header, summary, metrics, details/timeline/TI/related tables, MITRE, recommendations, Open Full Report button, footer) + subject `[LEVEL] verdict — INC-...` (subject `=={{` bug killed).
- Proof: INC-20261013-5596 (SSH), INC-20261013-5030 (phish, AI conf 0.85 live), INC-20261013-8877/3681. All success, failed_jobs empty. Live bug fixed: `file_hash` label leak → tiType().
- Human pending: Discord render, Gmail inbox. Live-vs-repo Correlate divergence confirmed again (companion events needed for replays).

## Notify v4 — email full values (2026-10-13)
- Email now full/copyable (hash 64-char, full AI reasons, caps 15) — Discord stays tight. Proof INC-20261013-8043 (phish 71, Gmail 13.2KB accepted, Discord 1739c delivered). 5 nits fixed (Rule prefix, metric label, `—`, engine phrasing, hottest-indicator headline).

## Risk v5 + TI connectors (2026-10-13, parallel)
- AbuseIPDB fixed (missing credential → 401s; now objects live INC-8092/9240). URLhaus fixed (dropped `threat` field; +15 fired live INC-7569 risk 55).
- ResponseGate v5: OTX tiered +3/+6/+10, cloud single-pub (was double). Offline 19/19; live INC-6800 (35 LOW), INC-2171 (61 MEDIUM, hash 65-mal). OTX/cloud tiers offline-only (TEST-NET cold; cloud replay blocked by source divergence).
- NULL-risk 32 excluded-not-backfilled (era TI unrecoverable). Test incidents left OPEN pending disposition.

## Reconcile DONE (2026-10-13)
- Live adopts repo: Correlate 24h+flag (+AttachReasons companion), StoreEvent explicit-ts+upsert, NormalizeAlert accepts cloudtrail. Partial +8 in same deploy (counter 427).
- Proof: SSH 8384/1707, cloudtrail 7728 (70 MEDIUM, DLQ flood ended), phish 3421 (+15 fired, 55), 5968 (31). failed_jobs zero from change. Collateral: 1 exec killed by deploy restart + 1 poller event lost to accidental docker restart (honest log in reconcile-report).
- Untouched: StoreDuplicate/DedupCheck/CaseStore-escaping divergences; StopLogging regex space; OTX live-tier; dispositions.

## Cloud fidelity batch (2026-10-13) — 6/6 live, one deploy
- Poller excluded from correlation (identity-based, stored but not correlated). Unknown fields omitted. Source split src_ip/src_host with dynamic labels. Cloud timeline uses action names. One TI no-match string. Same-action related reason.
- Proof: poller replay → no incident; AssumeRole IP → INC-6931; hostname → INC-5536 (Source hostname row, zero unknown-X); SSH/phish unchanged. failed_jobs zero. Counter 428.

## Round-2 (2026-10-13) — divergences closed
- 01 remainder repo→live (ctr 430, dedup proven). 02 auth chain: deployed by unknown concurrent writer, verified, skipped. 03 merged+deployed (render 200). 06 repo←live. NEW: F1 apostrophe-in-idem_key bug (unfixed, proposed); F2 dead `_evt` code.

## Notify v3 — Discord EMBED + 11 content fixes (2026-10-13)
- Embed: DiscordEmbed HTTP node (hardcoded webhook URL + ?wait=true; $env blocked instance-wide, scratch-verified). Proof: execution 9996 all-success, Discord returned message id (delivered), Gmail accepted. Incidents: INC-20261013-3018 (SSH, 75 HIGH), INC-20261013-3076 (phish, 61 MEDIUM, was 38), INC-20261013-5811 (phish fresh-IP, 71 MEDIUM).
- Content: TI-max risk (probes 65/85 exact), word-boundary AI summary + standalone confidence, 4-step playbooks, auth-only login line, MITRE ID+name, cell ellipsis, Unknown verdicts, explicit metrics, short hashes, Flag column, report button intact. Offline verify3.py 319/319 pass. failed_jobs: no new rows from this change.
- Left: Discord/Gmail client-side render (human); cloudtrail-source live-vs-repo divergence untouched; StoreDuplicate dedup self-refresh noted.

## Cloud fidelity (2026-10-13, live 01 counter 428 / 89418fe4)
- Replays: poller LookupEvents (stored dup, no incident), AssumeRole IP -> INC-20261013-6931 (29 LOW), AssumeRole hostname -> INC-20261013-5536 (24 LOW), SSH 5712/192.0.2.91 -> INC-20261013-2260 (35 LOW), phish benign/cold -> INC-20261013-4933 (31 LOW). All executions success (10278-10290); 4 Discord + 4 Gmail intentional.
- Poller proof: 5536 window 11 rows incl 4 poller -> Evidence 7 events, no poller IP, Related poller-free with 'same action' on 6931. Unknown proof: no unknown-X interpolations; hostname proof: 'Source hostname' row + 'from host'. TI proof: exact constant in live text, offline in embed/email. Regression: SSH/phish shapes unchanged. failed_jobs zero from change (3 pre-replay AI-OOM flakes only).
- Harness /tmp/opencode/cloud-fidelity/harness.cjs 34/34 on byte-identical deployed code. Full detail: /tmp/opencode/cloud-fidelity-report.md.
