# LIMITATIONS.md — known gaps, stated honestly (SOC-lead review, 2026-10-13)

Scope: lab/portfolio, NOT production. 21 cases attack-tested:
SSH brute/spray + success-after-failure, Windows logon (4624/4625) + AD
(kerberoast/AS-REP/NTDS), PowerShell/LOLBins, malware exec + hash/VT triage,
webshell + DVWA (SQLi/LFI), BOTS/Splunk multi-source replay, phishing
(lab-simulated), scanner ASN auto-close, C2 beaconing (Suricata),
impossible travel (Keycloak lab-simulated), DNS/file exfil, lateral movement
(single-host pattern), AWS CloudTrail account-takeover.

1. **Window semantics**: correlation/dedup anchored to alert timestamp
   (replay-correct), but late arrivals >15 min never re-link retroactively.
2. **No retention/pruning**: tables grow unbounded. Lab-safe; production needs
   ILM (30/90d) + disk alerts at 75/85%. 32 pre-scoring NULL-risk rows are
   excluded from calibration, not backfilled.
3. **No SLA/escalation paging**: HIGH risk only notifies Discord/Gmail; no
   on-call page, no ack deadlines, no MTTR metrics (the decision table already
   holds the raw data for future KPIs).
4. **Report + decision endpoints**: per-analyst tokens with anti-spoof, revoke,
   and an audit table (`analyst_decisions`) are live — but there are no RBAC
   roles, and block actions stay propose-only by design.
5. **TI coverage**: 4 sources live — VirusTotal (IP/file/URL) + AbuseIPDB +
   URLhaus + OTX, cache-first (24h/12h windows, error results never cached).
   Free-tier quotas (VT 4/min) survive bursts, not sustained load; no
   commercial feeds.
6. **AI layer**: free-tier models (503/429 common) → deterministic fallback
   covers outage, but inference quality varies; MITRE/confidence are
   model-narrated, not verified (`rule.mitre` propagation still open).
7. **Coverage, honestly labeled**: cross-host lateral needs a 2nd host
   (single-host service-install pattern only, INC-3693); no EDR fleet beyond
   Sysmon on one Windows host; phishing + impossible-travel are lab-simulated
   (Mailpit canary click; XFF-spoofed Keycloak pair) — a real internet inbox
   and real Entra ID (P1/P2) need paid tiers.
8. **Secrets**: n8n credentials + manager key file; no vault/KMS. VT key
   rotation DONE (old key 401s); X-SOC-Key rotation DONE 2026-10-10. Webhook
   replay guard live (X-SOC-TS ±300s window).
9. **Single-box failure domains**: n8n VPS reboot kills automation; manager
   reboot kills detection (observed). No HA. The integration is fire-and-forget:
   alerts in a bridge-down window are LOST (no retry).
10. **Adversarial robustness**: no alert signing; trust assumes the private
    network path (webhook key + timestamp gate, not mTLS). Scanner-ASN
    auto-close uses a hosting heuristic (documented assumption, 8 ASNs).
