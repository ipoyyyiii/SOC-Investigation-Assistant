# MEMORY.md — SOC Investigation Assistant (living context, update tiap sesi)

## 1. Apa ini
Otomasi investigasi SOC: SIEM alert → kumpul → korelasi → enrich TI → timeline → risk/gates → AI summary → notif (Discord+Gmail) → case DB → full report → analis mutusin TP/FP via endpoint. Automation BERHENTI di evidence+rekomendasi. Goal: porto GitHub/CV kelas enterprise, sekali testing mateng. BUKAN company/production.

## 2. Infra
- VPS n8n `18.138.203.100` (2vCPU/2GB + swap 4GB): n8n 2.41.6 Docker (`/opt/soc-n8n`, Postgres 16), bind 127.0.0.1:5678, akses `ssh -L`, `N8N_SECURE_COOKIE=false`. Wazuh agent 001 di sini (monitor auth.log + clamav scan.log).
- Wazuh host `13.212.120.162` (c7i-flex.large 4GB/80GB, Ubuntu 24.04, swap 4GB): full stack 4.14.8 all-in-one (manager+indexer+dashboard+filebeat, active). Dashboard https://13.212.120.162:443 admin (password di chat 07-10, SIMPAN, JANGAN commit).
- Jembatan: systemd `n8n-tunnel` (reverse 5679→localhost:5678), manager POST ke localhost:5679. Integration `custom-n8n` level≥7.
- AKSES TEMP GUE (soc-install key) MASIH NEMPEL di 2 host — cabut pas kelar + hapus key files + `00-lab.conf` (PasswordAuthentication yes, lab only).

## 3. Status phase (12) — 11.5/12
✅ 0,1,2a,2b(real E2E!),3,3.1(dedup+counts+outcome+breakthrough),4(TI VT+Abuse,UNKNOWN-safe),5(timeline),6(AI constrained+MITRE+conf+fallback chain),7(Discord+Gmail+report link),8(cases+iocs),9(decision endpoint),10(risk deterministik+gates propose-only),11(parsial: SSH/PS/hash/phishing/win-logon/persistence).
⏳ 11 sisa: web/C2/lateral (butuh sumber NetFlow/DNS), TI cache (DESAIN SELESAI, implementasi wavelet: skip-IF + pivot + writes — lagi dikerjain pas context ini ditulis, lanjutin!), full-report v1 DONE (workflow 03).
❌ Belum: Wazuh real tambahan (saat ini 1 agent), metrik SLA, pruning/retensi.

## 4. Workflows n8n (SPLIT done 2026-10-07: 01 = 20 orchestrator, 02 = 4, 03 = 7+, 04 = 20 enrichment, 05 = 7 AI)
01: Manual/Mock + Webhook/soc-alert → NormalizeAlert(multi-source+attack router) → DedupCheck → IsNew → (StoreEvent | StoreDuplicate+Counter) → Correlate(±15m) → AttachReasons(counts+timeline) → TICacheRead→Pivot→IFs→TI(VT IP,Abuse,VTFile,VTHash?/URL)+Writes → TIMerge → ResponseGate(risk+gates) → AI chain (Nemotron primary + Gemma/Lightning fallback) → FormatNotification → Discord+GmailNotify+CaseStore+ResponseLog.
02 (`02_SOC_Decision`): webhook /soc-decision → Validate(TP|FP|ESCALATE) → Decide(UPDATE) → Respond.
03 (`03_SOC_Report`): GET /soc-report?incident_id= → Qs → RenderReport HTML → Respond.
DB `soc`: soc_events, incidents(+status OPEN/TP/FP/ESCALATE, analyst_note, event_count), incident_iocs, incident_actions(PROPOSED), ti_cache(indicator,source,result,fetched_at).

## 5. Bug archaeology (jangan diulang!)
- `{{ }}` di dalam expression `={{ }}` = invalid; `=` prefix wajib di Fixed→Expression; `=={{` (dobel) kirim literal `=`.
- n8n `if` v1: `isEmpty('')`=false (cuma null/undefined true); string `equal` nggak reliable → pake number compare / isEmpty + null.
- Query 0 baris = rantai mati diam-diam → `alwaysOutputData` + pivot collapse single item.
- `$input` pindah pas node disisip (TI_URL) → referensi node eksplisit `$('X')` + try/catch.
- Publish UI vs DB: 2 penulis = conflict silent (versi basi). Protokol: single-writer + verifikasi pointer publishedVersionId.
- VT file UNKNOWN beruntun: hash 58char (recompute lokal, verifikasi MD5) → display ti[0] doang → $input shift. Sekarang: EICAR VT 65 mal ✅.
- Wazuh real: manager TCP-only (agent protocol=tcp); rule-id collision 87105 (punya VT ruleset) → range lokal 100010+; `<match>FOUND</match>` case-insensitive → kunci `<decoded_as>`; agent default TIDAK monitor auth.log; group plural `authentication_failures` vs singular; mock-default IP (`10.0.0.15`) mencemari alert real → default `''`.
- Grep self-match: pola `Failed password` selalu match COMMAND sudo sendiri → filter `grep -v COMMAND=`.
- Generate UUID valid 36 char buat versionId (gagal 2x karena 37 char).

## 6. Kredensial (nama doang, JANGAN tulis secret di sini!)
OpenRouter account, n8n Assistant model, Discord Webhook, Postgres account, VirusTotal account, Header Auth (AbuseIPDB), Gmail SMTP (app password). VT API key KEBACA di chat → WAJIB regenerate.

## 7. 7 fix arsitektur (deal: beresin dulu sblm coverage) — STATUS: 7/7 DONE (2026-10-07) (2026-10-07)
1. Auth webhook (secret check node pertama) — BELUM
2. Auth decision endpoint — BELUM
3. Simpen risk_score/level (+index) — BELUM
4. Breakthrough linkage (parent ke fail) — BELUM
5. Enrich top-3 related IP — BELUM
6. Window jangkar alert_ts (bukan NOW) — BELUM
7. Severity mapping; pruning/SLA/metrik/report-auth → tulis di README Limitations, BUKAN dibangun
Prinsip review: depth > breadth. Overkill boundary: 1-4 tampil di demo (gas), 6-7 invisible (parkir + tulis jujur).

## 8. Next (urut)
- [x] Sisa: idempotency, retro, per-analyst tokens (ALL DONE)
1. Selesaikan implementasi TI cache (lihat §3 ⏳) + verifikasi MISS/HIT.
2. Kerjakan 7 fix §7 (1+2 dulu: auth).
3. Coverage: phishing blast-radius, web normalizer+DVWA real, Win host real, C2/lateral (butuh sumber network).
4. Review total → README + .gitignore + LICENSE → push GitHub.
5. Cleanup: cabut akses temp, revert PasswordAuthentication, rotasi VT key.

 ini

## 10. File penting
- `PROJECTS.md` (spec), `workflows/01_SOC_Alert_Intake.json`, `02_SOC_Decision.json`, `03_SOC_Report.json`, `04_SOC_Enrichment.json`, `05_SOC_AIAnalysis.json`, `mocks/` (ssh, win-logon, email-phish), `tests/phase1-4.md` (log bukti!), `/opt/soc-n8n/docker-compose.yml`, workflow IDs: 01=`8YQs43dxYnlHZj09`, 02=`AN5wHypbRBZroWe5`, 03=`b3c4d5e6-f7a8-4b9c-9d0e-1f2a3b4c5d6e`.

## 11. Subagent runs (2026-10-07)
- Agent-3 reliability: TI 20s timeouts, 06_SOC_DLQ + failed_jobs wired 01/02/03, negatives 403 intact, live-DLQ test pending human.
- Agent-1 security: AuthCheck replay guard (X-SOC-TS ±300s, manual bypass), analyst identity required + analyst_decisions table, report token via app_config (IF_Auth+403), all negatives 403 verified, no secrets.
- Manager script now sends X-SOC-TS header (needs it or real alerts get rejected!).
- Agent-2 split: 04 enrichment + 05 AI via Execute Workflow nodes (CallEnrichment/CallAIAnalysis),  refs re-audited, full-path curl incl. TS+key = 3x success (parent+2 subs).

## 12. Coverage re-audit (2026-10-08, jujur ulang)
"Gabisa" kemarin sebagian males mikir. Revisi: evidence 8.5 + coverage 8 reachable TANPA infra baru.
- MITRE deterministik: propagasi rule.mitre (Wazuh rule asli bawa T-codes, terbukti 5760/5402) ganti LLM-ngarang. TODO.
- Parent-tree visual + signer display: data sudah tercapture, tinggal render. TODO.
- Skor obfuskasi PS deterministik (entropy/base64/IEX) + allowlist admin. TODO.
- Scanner auto-close: ASN statis + rule. TODO.
- Webshell real: DONE (2026-10-08) — nginx+php-fpm lab (upload.php intentional vuln) di host Wazuh, Nikto scan, rule 100011 (if_sid 31100 + match cmd=, T1505.003), E2E INC-20261008-4409. Gagalnya cuma DVWA penuh. Catatan: decoder web-accesslog sukses "nelen" rule match polos — harus anchor ke 31100.
- Suricata di manager (apt, monitor iface sendiri) = separuh jalan C2. TODO.
- Beneran mentok (infra/duid): mailbox real, host Windows real, IdP/Entra, EDR fleet, pcap skala.
- Test resources GRATIS: Atomic Red Team (eksekusi per-teknik MITRE + cleanup, jalan di Linux sekarang), BOTS dataset (korpus berlabel buat validasi evidence), malware-traffic-analysis.net PCAP (nanti pas Suricata), Metasploit (pas web branch), EICAR ✅ dipakai.
- Batch usul: MITRE-deterministik → parent display → obfuskasi → DVWA → BOTS-harness → scanner-ASN.

## 13. BOTS harness (started 2026-10-08)
- Downloading botsv1-attack-only.tgz (135MB) to /tmp/bots on n8n VPS (bg job).
- Plan: extract raw events from Splunk bucket journal.gz -> sample ~10 attack events (Security/Sysmon/suricata/http) -> translate to {source:'splunk',raw} envelopes -> fire webhook -> verify multi-SIEM claim with REAL Splunk data + score vs known BOTS answers.

## 14. Coverage STATUS TABLE (2026-10-08 malam — SUMBER RESMI, jangan hilang)

| Case | Status |
|---|---|
| Brute SSH/Linux + breakthrough | ✅ real E2E |
| Win 4624/4625 | ✅ kode, ❌ host real |
| Phishing | ✅ cabang+TI+playbook, ❌ blast-radius/klik real |
| Malware exec | ✅ hash+VT; visual tree ❌ |
| PowerShell/LOLBins | ✅ branch; skor obfuskasi + allowlist ❌ |
| BOTS specimen | ✅ sid7 pesan terverifikasi (lu tempel); sid0001/0002/0003 NGGAK terkirim (chain mati pre-fix, incidents row 0 — data jujur) |
| C2 beaconing/egress | ❌ butuh NetFlow/DNS |
| Webshell/web exploit | ✅ real E2E lab (2026-10-08): nginx+upload.php+webshell, rule 100011 T1505.003, INC-4409; DVWA penuh ❌ |
| Lateral RDP/SMB/PsExec | ❌ butuh host Windows + graph |
| Privesc file/cron | ✅ real (+FP case study grub) |
| Registry/task-win/kerberoast/LSASS | ❌ map bertahap |
| Defense evasion | ❌ rule map ringan |
| Impossible travel/MFA | ❌ butuh IdP |
| Scanner auto-close | 🔶 allowlist; ASN+auto-close ❌ |
| TI (VT IP/file/URL + Abuse + cache) | ✅ MISS+HIT; URLhaus/OTX ❌ |
| MITRE deterministik | ❌ (masih LLM, pernah halu T1542) |
| Timeline/risk/gates/decision/report | ✅ hidup |

Non-coverage kalimat:
1. Arsitektur: split 6 workflow + DLQ + idempotency + retro-link + anchored window + conflict guards — DONE, repo sinkron tanpa secrets.
2. Security: webhook/decision/report ber-auth + replay guard + token per-analyst anti-spoof + revoke — DONE; sisa rotasi VT key + cabut akses temp (aksi manusia).
3. Reliability: timeout TI 20s + DLQ terpasang — DONE kode, live-test DLQ nunggu klik UI manusia (nagkep StoreEvent sudah terbukti).
4. Ops-debt: HTTPS publik, pruning/retensi, PasswordAuthentication revert, README + push — BELUM, itu gerbang publish.

Risk formula (ResponseGate, deterministik, BUKAN AI): risk = 10 + rule_level*2 + min(30, VT mal*3+susp) + min(25, abuse_conf/4) + 40 if success_after_fail; ≥75 HIGH, ≥40 MEDIUM. Kandidat: bobot src_ip public + tipe attack (webshell RCE skrg cuma 30 LOW).

## 15. Keputusan jalur coverage (2026-10-08, user pilih)
- Windows lab (4624/4625, PS obfuskasi, lateral, kerberoast/LSASS/registry): SKIP dulu — menyusul (route mungkin PC user / Azure $200, belum ditentukan).
- Phishing: LAB SIMULASI (mailserver docker + Canarytoken klik-tracking + Wazuh), dilabel "lab-simulated" di README.
- Research hasil: Entra impossible-travel butuh P1/P2 = BERBAYAR (hard stop; alternatif Keycloak lab-simulated gratis). Mass inbox real = butuh domain/reputasi (paid) → pakai lab simulasi.
- Urutan kerja gratis-total sekarang: (1) normalizer web playbook+attack_type, (2) MITRE deterministik (propagate rule.mitre), (3) Suricata C2 beacon (apt+ET open, beacon Sliver/curl-jitter), (4) DVWA docker penuh, (5) scanner ASN auto-close (iptoasn/db-ip lite free), (6) URLhaus+OTX (auth.abuse.ch & OTX key gratis), (7) parent-tree render + obfuskasi score (coding), (8) Keycloak impossible-travel lab, (9) phishing lab simulasi, (10) README+push (gerbang publish: rotasi VT key, cabut akses temp).

## 16. Riset coverage & temuan normalizer (2026-10-08/09, BELUM dieksekusi — diskusi dulu)

### Riset: mana bisa gratis / nggak bisa (sumber: web research 2026-10-08)
- BISA gratis (udah ada plan): Suricata+ET open (C2 beacon, apt), DVWA docker, ASN free DB (iptoasn.com hourly TSV / DB-IP Lite CC-BY / IP2Location Lite), URLhaus Auth-Key gratis (auth.abuse.ch), AlienVault OTX key gratis, Keycloak self-host (MFA+impossible-travel SIMULASI), Mailpit/Mailu+Canarytoken (phishing SIMULASI), MITRE-propagate/parent-tree/obfuskasi (murni coding), GOAD-light (Orange Cyberdefense, 1-2 ISO Windows Server eval 180 hari, ~30GB/8-16GB RAM) kalo Windows route nanti.
- NGGAK BISA gratis: (1) Entra impossible-travel asli = Entra ID P1/P2 ($6+/user/bln) atau MDCA license — hard stop, alternatif cuma Keycloak lab-simulated (label jujur); (2) mass email ke inbox real = butuh domain+reputasi Workspace paid; (3) EDR fleet (CrowdStrike/S1) = trial lewat sales.
- Windows eval: Win10/11 Enterprise eval 90 hari (Microsoft Eval Center), Server eval 180 hari — legal gratis.
- MESIN INI nggak bisa Windows lab: 2 core/1.9GB/no VMX-SVM (vmx=0, svm=0), 44GB free. Docker ada tapi RAM mentok.

### AKAR BUG summary web "failed SSH login" (INC-4409) — ketemu di kode, belum difix
- NormalizeAlert: rules cek urutan isPersist/isWinLogon/isPS/isFile → else 'ssh-auth'.
- Alert 100011: groups ['local','web','web','attack'], desc 'Possible webshell command execution.' → nggak kena satupun → attack_type='ssh-auth' → branch fallback → outcome default 'failed_login' → AI summary ngarang "failed SSH login".
- Fix plan: tambah deteksi isWeb (/web|webshell|upload|cgi|sql.?inject/ di groups+description) SEBELUM fallback → attack_type 'web', outcome 'suspicious_request' (bukan failed_login), observables.url = d.url, src_ip = d.srcip (decoder web-accesslog udah isi). Plus playbook web (verify signature/hash osk-style, block IP proposal via gate).
- Prinsip: sumber halusinasi AI = field normalizer yang salah, bukan AI-nya — AI cuma nyebut apa yang di-normalize.

### Keputusan user (jangan dieksekusi sebelum diskusi selesai)
- Windows rows: SKIP dulu. Phishing: lab simulasi. Urutan & scope rencana lainnya masih DIBAHAS.

## 17. Coverage CASE-DRIVEN (resmi, 2026-10-08/09) — sumber + justifikasi

### Sumber riset
- Batch 1 (8 websearch + 2 webfetch, 1 gagal-429): THM SOC L1 path snippets, HTB Sherlock index (fetch sukses, 70+ case), job-description L1 (dangkal).
- Batch 2 (3 websearch): Verizon DBIR 2026 (PDF + snapshots), Mandiant M-Trends 2025/2026, LetsDefend (sudah bagian HTB; free tier terbatas).

### Angka real-world (buat justifikasi prioritas)
- Verizon DBIR 2026 (22,000 breaches): exploit vuln = **31% initial access** (naik dari 20%, KALAHKAN credential abuse 22%→13%); ransomware di **48% breaches** (tertinggi, naik dari 44%); human element **62% breaches** (retail snapshot 58%).
- Mandiant M-Trends 2025: exploits **33% initial infection** (terbanyak), global median dwell **11 hari** (naik dari 10). M-Trends 2026: dwell **14 hari**; initial access→handoff cuma **22 detik**.
- Catatan jujur: statistik = BREACH volume, bukan alert-queue volume. L1 nyata 90% waktunya alert berulang (brute/PUP/scanner) — di-situ auto-close + FP handling penting.

### Tabel kasus L1 → status kita
1 Alert triage & disposition — ✅ (decision endpoint+report) | 2 FP/benign — ✅ (grub FP + scanner auto-close planned) | 3 Phishing analysis — 🔶 (mailserver lab+Canarytoken, simulasi) | 4 Brute/password spray — ✅ live | 5 Success-after-fail — ✅ live | 6 Malware/hash triage+VT (ransomware family) — ✅ (EICAR, osk.exe) kandidat ransomware-SIM di lab | 7 Web shell+vuln exploit — ✅ webshell live + DVWA planned (DBIR #1 initial access!) | 8 C2/exfil — ❌ → Suricata+ET open (free) | 9 Lateral — ❌ Windows VM | 10 AD kerberoast/AS-REP/NTDS/LLMNR/NTLM — ❌ GOAD-light | 11 Insider/exfil file-DNS — ❌ parsial via Suricata-DNS | 12 AWS account takeover — ❌ CloudTrail (free tier mgmt events) ke Wazuh, replay skenario Nubilum-1 | 13 Impossible travel/MFA — ❌ Keycloak sim (Entra P1 paid) | 14 TI enrichment — ✅ (+URLhaus/OTX gratis) | 15 Case mgmt/report/escalate — ✅ | 16 Memory/disk DFIR — di luar L1 scope, skip | 17 Scanner auto-close — 🔶 ASN DB gratis.

### Rekomendasi prioritas (bukan setengah-hati)
- S1: Suricata C2 + DVWA (web exploit = DBIR #1 vector, C2 = bread-and-butter L1)
- S2: MITRE-deterministik + normalizer web fix (kualitas evidence, cepet)
- S3: ASN auto-close + URLhaus/OTX (noise reduction + TI realism)
- S4: Keycloak sim + phishing lab-sim + CloudTrail AWS (buka #12/#13/#3)
- S5: parent-tree render + obfuskasi score (coding)
- S6 (nanti): Windows GOAD-light → #9/#10/#Partial #11

## 18. Sweep 🔶 progress (2026-10-09)
- TI URL path: DONE live (OpenPhish URL -> 19 mal, INC-2188 risk 56). Found+fixed error-poison cache (21 rows purged, error-guard in 4 W_ nodes, wf04 v1db665c3).
- ASN auto-close: DONE live E2E. DB-IP lite 477k rows -> soc.ip_asn_cache + scanner_asn seed 8 ASN. 07_SOC_AutoClose (repo, secret-sanitized). n8n durable scheduler INACTIVE di instance ini -> host cron */5 + webhook + X-SOC-Key gate (wrong key -> exec error, proven). E2E: DO IP brute -> INC-8584 -> CLOSED_FP + analyst_decisions asn-autoclose.
- DB-only workflow lesson: need shared_workflow row (project ownership) + webhook_agent/entity row for trigger registration (cron scheduleTrigger would not fire even with active=t).
- VT key: n8n sudah pegang key ROTATED yang valid; key chat lama mati. C1 cleanup = DONE (VT).
- Sisa 🔶: phishing blast-radius (lab sim), PowerShell obfuscation score, Windows rows (deferred).

## 19. Sweep 🔶 progress-2 (2026-10-09 pagi)
- Obfuscation score: LIVE. Deterministic scorer in NormalizeAlert (powershell branch), allowlist downgrade, displayed in EVIDENCE block. INC-4240 obf_score 3 vs allowlisted run 0.
- BIG bug class fixed: template JSON-in-SQL cannot survive quotes -> raw_b64 (Code-node Buffer) + convert_from(decode(...))::jsonb. Lesson: NEVER interpolate JSON into n8n SQL templates via mustache; also n8n expressions don't support regex-literal .replace.
- Repo synced (01 + 07 workflows, secret-free).
- Remaining 🔶: phishing blast-radius (lab sim: Mailpit mailserver + click URL logged by Wazuh nginx access.log -> custom click rule), Windows rows (deferred), Discord verification of obfuscation line (human).

## 20. Sweep 🔶 FINAL status (2026-10-09)
- ✅ TI URL path (verdict asli 19 mal)
- ✅ TI cache error-poison FIXED (bukan cache error)
- ✅ ASN scanner auto-close LIVE (07 workflow, host cron, DB-IP lite, E2E INC-8584)
- ✅ Obfuscation score LIVE + allowlist (INC-4240 skor 3; allowlisted 0)
- ✅ Root-cause fix kelas-baru: JSON-in-SQL-template tidab aman -> raw_b64 + convert_from(decode())
- ✅ Phishing blast-radius LAB-SIM LIVE (Mailpit + rule 100012 T1566.002 + INC-8665)
- ⏸️ Windows rows tetap ditunda (keputusan user)
- ARTIFACTS: repo config/wazuh/{local_rules,local_decoder}.xml; mailpit container running; host cron */5 autoclose

---

## ⚠️ 21. PROTOKOL DOKUMENTASI (mandat user 2026-10-09 — WAJIB, bukan opsional)
Setiap selesai/berubah: diskusi, kerja, pengetahuan, planning, testing, bug, keputusan → LANGSUNG catat di MEMORY.md (+ tests/phase1-4.md buat evidence testing). Jangan nunggu diminta. Kalau ada hal nyangkut di chat yang belum kecatat (misal MuseSpark yang lagi error), CATAT + tanya. Ini sumber kebenaran antar-sesi.

## 22. COVERAGE STATUS FINAL (update 2026-10-09 pagi — sesudah sweep 🔶)

| Kasus | Status | Sisa |
|---|---|---|
| Brute force/password spray | ✅ live tested | — |
| Success-after-fail / breakthrough | ✅ live tested | — |
| Privesc file/cron | ✅ live tested (grub FP study) | — |
| Malware exec + hash/VT triage | ✅ live tested | visual tree |
| Webshell/web exploit | ✅ live tested (RCE nyata) | DVWA penuh |
| Multi-source (BOTS/Splunk) | ✅ live tested (sid7 verified) | harness scoring |
| Alert triage/disposition | ✅ live tested | — |
| FP/benign handling | ✅ live tested (grub 5x FP) | — |
| **TI enrichment** | ✅ live tested + **URL path live (19 mal)** | URLhaus/OTX |
| Timeline/risk/gates | ✅ live tested | bobot risk (kurang akurat) |
| Report/decision loop | ✅ live tested | — |
| **PowerShell/LOLBins** | ✅ **obfuscation score LIVE (3/10 cradle, 0 allowlisted)** | host Windows real |
| **Phishing** | ✅ **lab-sim LIVE (Mailpit delivery + klik → rule 100012 T1566.002 → INC-8665)** | inbox real (bayar/domain) |
| Win 4624/4625 | 🔶 kode (mock) | host Windows real |
| **Scanner auto-close** | ✅ **live E2E (ASN DB-IP lite, INC-8584 auto CLOSED_FP)** | — |
| C2 beaconing/egress | ❌ | Suricata + ET open (gratis) |
| Impossible travel/MFA | ❌ | Keycloak simulasi (Entra = bayar) |
| Insider/exfil file-DNS | ❌ | parsial via Suricata |
| Lateral RDP/SMB/PsExec | ❌ | butuh Windows |
| AD kerberoast/AS-REP/NTDS | ❌ | GOAD-light, butuh Windows |
| AWS account takeover | ❌ | CloudTrail free → Wazuh |

Hitungan: **14 ✅ live-tested · 2 🔶 (mock kode) · 5 ❌** (2 butuh Windows, 3 bisa gratis: Suricata/Keycloak/CloudTrail).

## 23. Backlog sesi ini (belum dikerjain, diskusi dulu)
1. Risk weight: public-IP + attack-type (webshell/phish/PS = 30 LOW kebablasan jujur rendah) — user concern 2026-10-08.
2. Suricata C2 (C2 beacon demo) — prioritas S1 riset DBIR (vuln exploit #1).
3. DVWA penuh (SQLi→RCE levels).
4. URLhaus + OTX keys (gratis) tambah sumber TI.
5. Keycloak impossible-travel lab-sim.
6. CloudTrail AWS account takeover (free mgmt events).
7. Parent-tree visual render.
8. BOTS harness scoring (tests/bots-score.md).
9. README + .gitignore + LICENSE + push (gerbang publish).
10. Publish gate human: rotate X-SOC-Key (key was exposed in chat earlier - rotate before publish), cabut SSH soc-install 2 host, revert PasswordAuthentication, hapus /tmp/soc-install*.

## 24. Yang lagi error/nyangkut (2026-10-09)
- User: "muse spark kaga bisa jalan" — BELUM jelas apa/apa errornya. Tanya user: aplikasi apa? error apa? (belum dijawab)
- Discord: pesan obfuscation line (INC-4240) + phish click (INC-8665) BELUM diverifikasi human di Discord.

## 25. Green-tail sweep 2 (2026-10-09 siang) — 2 dari 3 selesai
- Risk weight v2 ✅ (web/public/obf weights; webshell 35->50 MEDIUM; cross-node ref bug avoided)
- Web normalizer branch ✅ (attack_type web, INC-7358; AI hallucination "SSH login" root cause KILLED)
- Process chain render ✅ (report page; osk.exe->taskkill->hash table; NaN concat bug fixed)
- Sisa green-tail: BOTS harness scoring (next), DVWA penuh, URLhaus/OTX (BUTUH KEY dari user — daftar abuse.ch + OTX), Windows host (deferred), inbox real (paid).
- LIMITATIONS tambahan: bridge down = alert lost (no retry); report uses ?key=report_token (app_config), not analyst token.

## 26. BOTS harness + DVWA progress (2026-10-09 siang)
- BOTS harness DONE: /tmp/bots_sample.py + /tmp/bots_harness.py (script replay + skor DB). Sample 10 Sysmon ProcessCreate dari dataset attack-only (osk.exe->vssadmin/wmic/schtacks/powershell sequence). Skor: 10/10 stored, 10/10 attack_type=process, 10/10 parent+command+hash preserved, 9/10 incident (1 dedup benar), 9/9 TI live. Hasil: tests/bots-score.md.
- DVWA PENUH: docker.io lagi diinstall di host Wazuh (background) -> plan: containers dvwa+mariadb, nginx proxy /dvwa/, custom rules SQLi/LFI/CMDi (100013-15, T1190), serang dari VPS, verifikasi alert -> incident (web branch) -> risk.
- Green-tail sisa sesudah ini: URLhaus/OTX (BUTUH key user), Windows host (deferred), inbox real (paid).

## 27. Green-tail sweep FINAL (2026-10-09) — semua yang gratis beres
- Risk v2 ✅ | Web normalizer ✅ | Process chain render ✅ | BOTS harness ✅ (10/10) | **DVWA penuh ✅ E2E (SQLi/LFI exploited, INC-8316 50 MEDIUM)**
- Sisa hijau HANYA yang butuh user/paid: URLhaus+OTX (butuh key gratis dari user: auth.abuse.ch + otx.alienvault.com), Windows host (deferred), inbox email real (paid).
- Lab baru: docker.io + DVWA + MariaDB di host Wazuh (127.0.0.1:8080, lewat nginx /dvwa/), mailpit di VPS n8n (SMTP 1025/API 8025), host cron */5 autoclose.
- Lessons: ^~ wajib vs regex php location; POST body nggak ke access.log; CSRF field namn DVWA = seclev_submit; urllib redirect handling butuh manual.

## 28. URLhaus + OTX DONE (2026-10-09) — 4 sumber TI live
- Live: INC-2098 risk 35->60 MEDIUM. OTX 29 pulses, URLhaus malware_download(online, ELF payload), VT 5mal/3mal.
- Cred IDs: URLhaus uRlHaUs9000aa11b2c3d4e5f6071829304 (header Auth-Key), OTX xzk0E7010q7Sjn6a (X-OTX-API-KEY). URLhaus API host = urlhaus-api.abuse.ch (main host bot-gated). HTTP node WAJIB explicit method POST.
- Lesson besar: (a) HTTP node error replaces flow item {error} -> RestoreItem wajib setelah node error-prone; (b) jangan parallel-branch dari trigger (sub-workflow return salah node output) -> linear; (c) credential n8n: header name harus persis.
- SISA: FormatNotification + CaseStore masih pakai template .replace(/'/g) -> convert ke b64 (bug menunggu apostrophe); Discord line URLhaus/OTX belum diverifikasi human.

## 29. C2/Suricata DONE + sisa 2 item gratis (2026-10-09)
- Suricata E2E LIVE: INC-6709 rule 100016 T1071. Files: config/wazuh/{local_rules,local_decoder}.xml updated; tests/tools/suricata_bridge.py; systemd suricata-bridge.service.
- Sisa item ❌ gratis: CloudTrail AWS takeover (cek instance role/aws cli dulu), Keycloak impossible-travel (subagent plan sudah siap: KC 26.8 + KC_PROXY_HEADERS=xforwarded + X-Forwarded-For spoof 2 geo + detect haversine >900km/h + POST source=keycloak).
- Keycloak: docker di VPS n8n (memory 1.4GB limit), realm soc, user jane.doe, events jboss-logging, admin REST read events, geo DB-IP, detector, poller ke webhook.

## 30. Suricata C2 + Keycloak DONE (2026-10-09) — tinggal 1 item gratis
- C2: INC-6709 rule 100016 T1071 (suricata->bridge->wazuh->n8n).
- Impossible travel: INC-1615 risk 79 HIGH (Keycloak lab, XFF-spoofed geo pair, haversine>900km/h).
- AWS account takeover: BLOCKED butuh user (IAM access key cloudtrail:LookupEvents) — taruh di VPS /root/aws creds file, nanti gue wire. Tanpa itu ❌ tetap.
- Coverage count terbaru: 16 ✅ live-tested · 1 🔶 mock · 4 ❌ (AWS-butuh-key, Lateral+AD-butuh-Windows, Insider/DNS-exfil-parsial).

## 31. Windows lab LIVE (2026-10-09/10) — 4 dari 5 Windows rows hijau
- Windows Server 2022 AWS VM (47.129.220.252, c7i.flex-large 4GB/40GB, ~$0.12/h) + Wazuh agent 002 (win-lab-01) + Sysmon64. Remote via WinRM (VPS) + RDP (user).
- E2E incidents: INC-8377 (4625 brute T1110), INC-5842 (4624 success T1078), INC-7919 (PS obfuscation T1059.001, risk 45 MEDIUM), 100024 (7045 service install T1543.003).
- Coverage update: Win 4624/4625 ✅ live; PowerShell/LOLBins ✅ real host now; Lateral 🔶 single-host pattern (sc.exe service, no 2nd box).
- BELUM: AD DS forest (Install-WindowsFeature success=False) -> kerberoast/AS-REP/NTDS.dit tetap ❌.
- Rule lesson: custom rule HARUS if_sid/if_group ke rule parent yang bener (root rule ke-reset kalah sama ruleset). 100023 pakai if_group sysmon_event1 + pcre2 commandLine.

## 32. Windows AD LIVE (2026-10-10) — Kerberoast + NTDS + semua
- DC promoted (corp.lab), 6 attack patterns E2E: 4625/4624/PS-obf/service-install/kerberoast/NTDS-dump.
- INCidents: 8377, 5842, 7919+3924, 3693, 1903 (T1558.003), 9472 (T1003.003).
- Coverage: Win 4624/4625 ✅ live; PowerShell ✅ real host; Lateral 🔶 single-host; AD kerberoast/AS-REP/NTDS ✅ live (kerberoast+dump proven; AS-REP executed, RC4 rule pending).
- Remaining: lateral cross-host (VM kedua), insider-exfil DNS live demo, AWS CloudTrail (butuh IAM key user), README/push, rotasi secrets.

## 33. A-list sweep DONE (2026-10-10)
- Insider/exfil DNS: LIVE E2E (INC-7107 T1048.003 + T1071.004). Rules 100017/100018. Bridge restart required after suricata restart.
- Gmail: verified working post-split.
- CaseStore b64: apostrophe landmine fixed via notification_b64/ti_b64 + convert_from/decode. INC-8130 proof.
- COVERAGE FINAL: 18 live-tested / 3 lab-sim / 1 parsial (none left parsial? insider-exfil now LIVE) / 1 butuh-user (AWS IAM key).
- Sisa: AWS CloudTrail (butuh IAM key user), lateral cross-host (opsional VM#2), README+gitignore+LICENSE+push, rotate X-SOC-Key, revoke temp SSH.

## 34. AWS CloudTrail LIVE (2026-10-10) — SEMUA ROW coverage kelar
- INC-7019 cloudtrail-stoplogging risk 75 HIGH (attacker denied, detected). Poller: tests/tools/soc_cloudtrail.py, cron */5 on VPS.
- COVERAGE: 19 live-tested / 3 lab-sim / 1 single-host (lateral) / 0 #butuh-user. ALL 21 KASUS DONE (label jujur: lab-sim + single-host).
- SISA murni publish gate: README draft, .gitignore, LICENSE, rotate X-SOC-Key, revoke SSH temp, secret scan, git push.

## 35. X-SOC-Key ROTATED (2026-10-10) — akses tetap jalan
- Key lama (bocor di chat) MATI: intake 403, autoclose reject. Key baru 64-hex di /root/soc-key (VPS, root 600, TIDAK di chat/repo).
- Consumers updated: n8n credential SOC Webhook Key (delete+reimport same id via CLI), 07 AuthCheckAC EXPECT (DB publish), ubuntu cron autoclose, /usr/local/bin/soc-cloudtrail.py, /var/ossec/etc/soc-webhook.key (sha256 VPS==Wazuh MATCH). n8n restarted, verified E2E.
- Repo 07 re-synced dengan placeholder (tanpa key). Probe incident INC-5918 dibersihkan.
- SENGAJA BELUM (biar user tetap bisa kerja): revoke SSH soc-install (assistant butuh), analyst tokens, report_token, Discord/Gmail/OpenRouter/VT/OTX/URLhaus creds, Wazuh dashboard admin. Semua itu pre-publish gate, bukan sekarang.
- Cara pakai key baru buat curl manual: K=$(sudo cat /root/soc-key); curl ... -H "X-SOC-Key: $K" -H "X-SOC-TS: $(date +%s)" ...

## 36. Notification UX rework (2026-10-12) — ENGLISH ONLY, deployed live
- Problem: FormatNotification output hard to read (verdict buried mid-EVIDENCE, raw snake_case labels, numbers without context, success/fallback format divergence, blind 1900-char slice eating the report link, `--- CAPS ---` headers). User mandate: ENGLISH ONLY, never Indonesian.
- New template (verdict → incident → why → AI → evidence → actions → MITRE Rules-vs-AI → timeline max 5 → report link + NOTE): Discord markdown, human labels, deterministic playbooks both paths, smart truncate (middle first, header+link+NOTE never cut). AI observed/next-steps dropped (AI summary kept); rule MITRE always shown even when AI down.
- Deploy: backup /tmp/opencode/notify-rework/backup-01-20261012-222156.json; live 01 versionId e51bc8e7 (was b05b12d4), counter 420, active. Changed ONLY FormatNotification jsCode + GmailNotify text `=={{`→`={{`. Repo workflows/01_SOC_Alert_Intake.json synced (1 file, 2 hunks), secret scan clean. Offline work: /tmp/opencode/notify-rework/ (new js + harness + samples.md, 4 cases).
- Live proof: INC-20261012-2431 (SSH, 1593 chars) + INC-20261012-6543 (phish, 1676 chars), both ≤1900, Discord delivered, link+NOTE intact. AI rate-limited → fallback path exercised LIVE (single-line fallback correct). AI-success path covered offline only.
- Nits fixed: pluralization (1 user/IP/incident), `mal`→`malicious`, OTX pulse/pulses.
- DELIBERATELY LEFT: GmailNotify subject `=={{` bug; AI-success live test; Discord-client visual check; other attack types live.
- PRE-EXISTING DIVERGENCE FOUND (not caused by deploy, needs separate task): live Correlate = 15-min window + no alwaysOutputData (repo = 24h + flag) → phish replay stalled once at Correlate; live StoreEvent uses NOW() (repo explicit ts); live NormalizeAlert rejects cloudtrail source → background soc-cloudtrail.py errors (218+, DLQ-caught). Recommend: reconcile live vs repo as its own task before next coverage work.

## 37. Notify v2 — Discord card + HTML email (2026-10-13, enterprise-style)
- Design ref: Sentinel incident email template (header+severity badge, exec summary, metrics, timeline, MITRE, recommendations, entity/alert tables, investigate button, footer). Zero emoji everywhere (user rule: PROJECT ARTIFACTS ENGLISH-ONLY, chat language free).
- Formatter outputs 3 fields: notification_text (Discord plain ≤1900) + email_subject (`[LEVEL] verdict — INC-...`) + email_html (inline CSS, max-width 700px, severity color header, tables for details/timeline/TI/related, Open Full Report link, footer). Empty fields omitted (no "none"); actions always numbered; REPORT_BASE_URL='' (no public report host — relative path, don't hardcode).
- Deploy: live 01 versionId f5242e9f (backup backup-01-20261013-090323.json); changed ONLY FormatNotification jsCode + GmailNotify (subject/html/emailFormat=HTML). Discord node untouched. Repo 01 synced (2 hunks), secret scan clean. Offline: FormatNotification.v2.js + harness2.cjs + v2samples.md + verify2.py (90 checks pass).
- Live proof: INC-20261013-5596 (SSH 1514c), INC-20261013-5030 (phish 1885c, AI-success conf 0.85 LIVE), INC-20261013-8877/3681 (LOW). All success, failed_jobs empty, Discord+Gmail nodes executed. Bug found+fixed live: TI `type: file_hash` snake_case leak → tiType() map + redeploy v2b.
- Known live-vs-repo divergence CONFIRMED again: replay without companion stalls at Correlate (0 rows, no alwaysOutputData live) — incidents still stored; use companion events for tests. Reconcile task still open.
- Human verification pending: Discord client render, Gmail inbox arrival/render.

## 39. Notify v4 — email full values (2026-10-13)
- Trigger: user caught 2 valid flaws — evidence hash shortened in EMAIL (unpivottable) + AI reasons cut mid-sentence (email reused Discord-trimmed content).
- Fix: split budgets — email ≈ no truncation (full 64-char hash + full URL with word-break, full AI reasons, timeline/related/TI cap 15, `...` only >2000-char safety-net); Discord keeps tight trim + short hash. Plus 5 nits: Rule prefix dropped, middle metric label removed, `not checked`→`—`, `66/66`→`flagged by N engines`, hottest indicator headlines Why+embed.
- Live: FormatNotification v4 (counter 425, backup backup-01-20261013-105144.json). Proof INC-20261013-8043 (phish 71 MEDIUM, AI conf 0.85): Discord 1739c delivered, Gmail 13.2KB accepted 250 OK. failed_jobs: only known cloudtrail divergence. Detail: /tmp/opencode/notify-rework/v4-report.md.
- Trade-off: email ~12KB HTML. TI counts vary run-to-run (live re-queries: 63/65/66 seen) — expected, not a bug.

## 38. Notify v3 — Discord EMBED + content fixes (2026-10-13, ENGLISH ONLY)
- Scope A: Discord node replaced by HTTP Request node DiscordEmbed (POST hardcoded webhook URL + `?wait=true`, body `{{ JSON.stringify($json.discord_embed) }}`). Formatter emits 4th field `discord_embed` ({username "SOC Monitor", embeds[1]: title `[LEVEL] INC — verdict (risk N/100)`, description = exec summary, color HIGH 15158332 / MEDIUM 15105570 / LOW 16776960, fields Rule+Host+User+Metrics+Threat intel+MITRE inline + Actions/Timeline/Full report full-width, footer analyst note, timestamp alert ts; limits enforced 6000/1024/25, zero emoji). `$env` is BLOCKED in this n8n instance (ExpressionError in Code AND expressions, verified via scratch workflow) → documented fallback: hardcoded URL in node, placeholder in repo. CaseStore unchanged (notification_text).
- Scope B (all 11): B1 ResponseGate TI per-indicator MAX (VT cap 30 / abuse cap 25 / urlhaus +15 / otx +10, object-guarded) — phish 38→61 MEDIUM live (hash 63-mal counted, was ignored as ti[1]); SSH 60→75 HIGH (OTX 50 now counted). B2 AI summary word-cut + standalone "AI confidence: N." B3 every playbook exactly 4 steps. B4 login-success line auth-only; Why strong-first (public-IP filler dropped when strong reasons exist). B5 MITRE rule "ID Name" via MITRE_NAMES (local_rules.xml IDs). B6 email cells word-cut + ellipsis. B7 urlhaus-{unknown}/OTX-0 shaped records no longer verdict Suspicious → Unknown/Clean. B8 "4 IPs / 3 users". B9 middle-short hashes in tables (full in title attr). B10 timeline Flag column. B11 report button verified in HTML + Gmail accepted.
- Deploy: backup backup-01-20261013-092553.json; live 01 a07c57f8 (counter 423) then 85a8285f (counter 424, +?wait=true); import deactivates in regular mode → reactivate via update:workflow + force-recreate restart (webhook registration). Repo 01 synced (3 nodes, placeholder URL), secret scan clean. Offline: FormatNotification.v3.js + ResponseGate.v3.js + harness3.cjs + v3samples.md + verify3.py (319 checks pass). Live proof: INC-20261013-3018 (SSH 75 HIGH), INC-20261013-3076 (phish 61 MEDIUM), INC-20261013-5811 (phish 71 MEDIUM, execution 9996 ALL 16 nodes success, Discord msg id returned = delivered, Gmail accepted). failed_jobs: zero new rows from this change (only background cloudtrail-poller NormalizeAlert rejects = known divergence). Discord posts total: 3 (2 pre-fix 204s + 1 verified). New finding: StoreDuplicate re-inserts soc_events rows, so the 15-min dedup window self-refreshes — replays need fresh indicators, not just waiting.
- Human verification pending: Discord client render of embed, Gmail inbox render (button), AI-down live path on v3.
