# SOC Investigation Assistant

**Wazuh SIEM + n8n automation → alert triage, enrichment, risk, evidence-backed notification, analyst decision loop. Built and attack-tested against real tooling (Atomic Red Team, BOTS/Splunk, DVWA, Kerberoast, Suricata, Keycloak, CloudTrail).**

> **Scope, stated honestly:** this is a *portfolio lab* — production-*shaped*, lab-*proven*. Every detection below was executed against a real target and verified end-to-end, but the system runs on a single small VPS with lab constraints documented in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). Items that used synthetic/spoofed data are labeled as such.

---

## Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │                     DATA SOURCES                       │
                    │  Wazuh agents (Linux+Windows) · Suricata eve.json      │
                    │  Splunk events (BOTS) · Email gateway · Keycloak       │
                    │  AWS CloudTrail                                        │
                    └───────────────┬────────────────────────────────────────┘
                                    │ webhook /soc-alert (HMAC-ish key + timestamp window)
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  01_SOC_Alert_Intake (n8n)                                                    │
│  Normalize (multi-source router) → Dedup (idempotency key) → Correlate (±15m  │
│  anchored to alert ts, +24h retro-link) → Call 04 Enrichment → ResponseGate   │
│  → Call 05 AI → FormatNotification → Discord + Gmail + CaseStore + Report     │
└──────────┬──────────────────────────────┬─────────────────────────────────────┘
           ▼                              ▼
┌─────────────────────────┐   ┌──────────────────────────────────────────────┐
│ 04_SOC_Enrichment       │   │ 05_SOC_AIAnalysis                            │
│ TI cache-first: VT      │   │ Summary + observed evidence + MITRE + next   │
│ (ip/file/url) ·         │   │ steps. Falls back to FACTS-ONLY if the model │
│ AbuseIPDB · URLhaus ·   │   │ is unavailable — never invents evidence.     │
│ OTX                     │   │ Deterministic risk is NEVER computed by AI.  │
└─────────────────────────┘   └──────────────────────────────────────────────┘
           │
           ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ Postgres (soc): soc_events · incidents · ti_cache · incident_iocs ·           │
│ analyst_decisions · analyst_tokens · ip_asn_cache · scanner_asn · failed_jobs │
└───────────────────────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
  02_SOC_Decision (TP/FP/      03_SOC_Report (HTML evidence page) ·
  ESCALATE, per-analyst        06_SOC_DLQ (failed-job capture) ·
  token + audit)               07_SOC_AutoClose (scanner-ASN FP autoclose)
```

**Core design decision:** risk + gates are *deterministic formulas* you can read; the LLM only narrates and recommends. If the LLM is down, notifications degrade to facts, not fabrications.

---

## Live coverage (21 cases, every one attack-tested)

**Legend:** ✅ live-tested end-to-end · 🟡 live but lab-simulated/single-host (labeled) · ❌ blocked (reason stated)

| Case | Status | Evidence |
|---|---|---|
| Brute force / password spray | ✅ | Wazuh SSH + Windows 100021 (T1110) incidents |
| Success-after-failure (breakthrough) | ✅ | same-IP parent linkage; Windows 4624→100022 (T1078) |
| Privesc file/cron | ✅ | Atomic Red Team T1053.003; **5 real bootloader FIM alerts closed FP by analyst** |
| Malware exec + hash/VT triage | ✅ | EICAR (VT 66-mal), BOTS osk.exe; process-chain render in report |
| Webshell / web exploit | ✅ | real RCE webshell (rule 100011, T1505.003) **and** DVWA SQLi/LFI exploited (T1190) |
| Multi-source intake (Splunk/BOTS) | ✅ | BOTS attack-only replay, harness **10/10 field-preservation** ([`tests/bots-score.md`](tests/bots-score.md)) |
| Alert triage & disposition | ✅ | decision endpoint, analyst identity, anti-spoof, revoke |
| FP / benign handling | ✅ | grub/shim case study + ASN-based auto-close (INC-8584, DB-IP 477k ranges) |
| Threat-intel enrichment | ✅ | **4 sources live**: VT + AbuseIPDB + URLhaus + OTX (cache-first, 0-API cache hits) |
| Timeline / deterministic risk / gates | ✅ | formula-driven (web +15, public-IP +5, URLhaus +15, OTX tiered +3/+6/+10…); propose-only block |
| Report + analyst decision loop | ✅ | HTML evidence page; TP/FP/ESCALATE with audit table |
| PowerShell / LOLBins | ✅ | deterministic obfuscation score **+ real execution on Windows host** (INC-7919, T1059.001) |
| Phishing | 🟡 | lab mailserver + canary click → rule 100012 (T1566.002) → INC-8665 |
| Windows 4624/4625 | ✅ | real Security-log events from AWS Windows VM (INC-8377/5842) |
| Scanner auto-close | ✅ | ASN lookup + deterministic FP autoclose, E2E |
| C2 beaconing / egress | ✅ | Suricata + custom rule → Wazuh 100016 (T1071) → INC-6709 |
| Impossible travel / MFA | 🟡 | Keycloak lab, geo-separated logins → INC-1615 **risk 79 HIGH** (Entra-asli needs P1/P2) |
| Insider / exfil (DNS/file) | ✅ | Suricata DNS exfil rules → Wazuh T1048.003 → INC-7107 |
| Lateral movement (PsExec/RDP/SMB) | 🟡 | single-host service-install pattern (INC-3693, T1543.003); cross-host needs 2nd host |
| AD kerberoast / AS-REP / NTDS | ✅ | Rubeus kerberoast → 4769 `0x40810000` (T1558.003, INC-1903); NTDS shadow-copy attempt (T1003.003, INC-9472) |
| AWS account takeover | ✅ | read-only creds abuse demo: StopLogging/CreateAccessKey denied → INC-7019 **risk 70 MEDIUM** |

**Score: 18 live-tested · 3 lab-simulated (labeled) · 0 untouched.** Attack techniques were chosen from real-world prevalence data (Verizon DBIR 2026: exploit-vuln 31%, credential abuse 13%, ransomware 48%; Mandiant M-Trends: exploits 33% initial vector) — and honest labels are kept where the demo is not real-world.

---

## Detection pipelines actually shipped

- **Deterministic evidence block** in every notification: event counts, distinct IPs/users, TI verdicts with engine counts, retro-links, success-after-failure flag, obfuscation score, process chain.
- **Risk formula** (`ResponseGate`, readable in [`workflows/01`](workflows/01_SOC_Alert_Intake.json)): `10 + rule_level×2 + source weights`, e.g. web-exploit +15, public src +5, URLhaus-malware +15, OTX-pulses tiered +3/+6/+10 (1–9/10–29/≥30 pulses), auth-breakthrough +40.
- **Notification hygiene**: source-aware labels, per-`attack_type` triage playbooks, TI skipped for non-IP indicators, 1900-char Discord cap with detail in the report page.
- **Reliability**: TI timeouts 20s, DLQ captures failed jobs, idempotency keys (double-POST → 1 row), always-output guards on branching queries, base64-encoded payloads to survive quotes/AI text in SQL.
- **Security**: webhook + decision endpoints authenticated, timestamp replay window, per-analyst tokens with anti-spoofing and revoke, analyst decision audit table, block actions propose-only.

---

## Repo layout

```
workflows/     7 n8n workflows (intake, decision, report, enrichment, AI, DLQ, autoclose)
config/wazuh/  local rules + decoders (Linux FIM, Windows 4625/7045/4769, web, suricata, DNS)
mocks/         replay envelopes for wazuh/email sources
tests/         phase1-4 evidence log, BOTS score, tooling (harnesses, detectors, pollers)
docs/          LIMITATIONS (honest gaps), TEST-MATRIX (feature status)
```

## Run it

```bash
# 1. Wazuh manager + agents (Linux + Windows), n8n + Postgres via docker compose
# 2. Import workflows/*.json into n8n, set credentials: Postgres, VT, AbuseIPDB,
#    URLhaus (header Auth-Key), OTX (header X-OTX-API-KEY), OpenRouter, Discord, Gmail
# 3. Point Wazuh integration custom-n8n at http://<vps>:5678/webhook/soc-alert
# 4. Replay: mocks/*.json, BOTS dataset (tests/tools/bots_harness.py),
#    Atomic Red Team, or real traffic to the lab
```

Full setup notes and attack-replay steps are in [`tests/phase1-4.md`](tests/phase1-4.md) — written as an evidence log, including every bug found and root-caused.

## Honest next steps (known gaps)

1. **FP/TP metrics dashboard** — the decision table already has the data for SOC KPIs.
2. **MITRE propagation from `rule.mitre`** instead of LLM output for the final step of the anti-hallucination chain.
3. **Scale validation** (thousands of events/min), pruning/retention, TLS, pipeline self-monitoring.

Details: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) · [`docs/TEST-MATRIX.md`](docs/TEST-MATRIX.md)

---

*Built by one person as a portfolio project. Everything marked ✅ was executed against a real target in a lab; everything else is labeled. No production claims.*
