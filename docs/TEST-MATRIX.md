# Test Matrix — status per fitur (2026-10-08/09)

Legend: ✅ built+tested (evidence in tests/phase1-4.md) | ⚠️ built, under-tested | ❌ not built | 🧹 cleanup needed

## A. Built + tested
| # | Feature | Evidence |
|---|---------|----------|
| A1 | Webhook intake + X-SOC-Key/X-SOC-TS auth + replay guard | 403 anon/wrong, real alerts flow |
| A2 | Idempotent dedup (idem_key + ON CONFLICT) | 2x identical POST -> 1 row |
| A3 | Correlate 15-min window anchored to alert ts | fix #6 (replay 09:16 -> 09:15 cluster) |
| A4 | Retro-link 24h same-IP | 7504 -> 7796 |
| A5 | TI VT ip + AbuseIPDB + cache MISS/HIT | 0 new API calls on HIT |
| A6 | Deterministic risk + gates + severity mapping | 31 LOW / 71 MEDIUM cases, stored+indexed |
| A7 | AI summary + fallback chain + facts-only mode | Phase 5-6, 503-safe |
| A8 | Notification: Discord (+Gmail parallel) | T1-T4 human check PASS |
| A9 | Decision endpoint TP/FP/ESCALATE + analyst identity + anti-spoof + revoke + audit | alice-lead/bob-tier1 suite |
| A10 | Full report page | INC-20261006-9938 |
| A11 | Split into 6 workflows + DLQ errorWorkflow wiring | 01/02/03 errorWorkflow |
| A12 | DLQ actually catches failures | StoreEvent invalid-syntax -> failed_jobs row |
| A13 | SSH brute force real E2E | 127.0.0.1 x10 -> incident + Discord |
| A14 | ClamAV + EICAR real E2E | rule 100010, VT 66-mal |
| A15 | Privesc cron/FIM real + grub FP case study | T1053.003; 5 alerts closed FP by analyst |
| A16 | Webshell real E2E | rule 100011 T1505.003, INC-4409 |
| A17 | Multi-source Splunk BOTS replay | sid7 Discord verified (parent masquerade, hash, T1036+T1059) |

## B. Built but under-tested (SWEEP TARGETS)
| # | Feature | Gap |
|---|---------|-----|
| B1 | TI URL source (W_URL path) | DONE 2026-10-09: live verdict 19 mal (usps-email.com); error-poison guard added |
| B2 | Elastic + Sentinel normalizers | code exists, NEVER executed |
| B3 | Gmail delivery | content verified vs Discord; actual inbox arrival not re-checked post-split |
| B4 | Phishing branch (source=email) | mock-only (Phase 11); no blast-radius/click data |
| B5 | Windows branch 4624/4625 | mock-only; no real Windows host |
| B6 | PowerShell branch | mock-only; obfuscation score not built |
| B7 | Report page post-split (03_SOC_Report) | 1x verified pre-split; not retested after split |
| B8 | DLQ manual pin/force-fail test | auto-catch proven; UI pin test pending |
| B9 | Discord 1900-char truncation | by design (see LIMITATIONS) — confirm acceptable |
| B10 | TI cache error-poison | FIXED 2026-10-09: error results no longer cached; 21 poisoned rows purged |
| B11 | Risk formula systematic scoring | per-case verified; no suite (BOTS harness planned) |
| B12 | MockWazuhAlert / test-trigger node | dev utility — confirm documented pre-publish |

## C. Cleanup (pre-publish, human/security actions)
| # | Item | Status |
|---|------|--------|
| C1 | Rotate VirusTotal API key (exposed in chat + on disk) | 🧹 PENDING |
| C2 | Revoke temporary SSH key soc-temp-install on BOTH hosts | 🧹 PENDING |
| C3 | Revert PasswordAuthentication on Wazuh host | 🧹 PENDING |
| C4 | Remove /tmp/soc-install + soc-install.pub key files | 🧹 PENDING |
| C5 | Rotate X-SOC-Key (exposed) on Wazuh integration + n8n credential + 07 node + crons + poller | ✅ DONE 2026-10-10 (old key 403s) |
| C6 | Repo secret scan before push (workflows/ no keys) | 🧹 PENDING |

## D. Not built (roadmap, see MEMORY.md §15-17)
DVWA full, Suricata C2, ASN auto-close, URLhaus/OTX, MITRE-propagate, parent-tree render, obfuscation score, Keycloak sim, phishing lab-sim, CloudTrail AWS, Windows rows (deferred).


## Update 2026-10-09
- B1, B10 -> DONE (tests/phase1-4.md).
- Scanner auto-close row now LIVE E2E (docs/TEST-MATRIX.md B-list superseded): see tests/phase1-4.md section "Scanner ASN auto-close".
- New finding documented: n8n durable scheduler inactive on this instance -> cron workflows must use webhook + host-cron.


## Update 2026-10-09 siang
- Green-tail sweep: risk v2 (web 40->50 MEDIUM), web normalizer branch (attack_type=web, kill AI SSH-hallucination), process chain render (report page), BOTS harness 10/10 (tests/bots-score.md).
- DVWA: in progress.
