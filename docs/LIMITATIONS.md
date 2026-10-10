# LIMITATIONS.md — known gaps, stated honestly (SOC-lead review)

Scope: lab/portfolio, SSH+Windows-logon+PowerShell+file+email. NOT production.

1. **Window semantics**: correlation/dedup anchored to alert timestamp (replay-correct), but late arrivals >15 min never re-link retroactively.
2. **No retention/pruning**: tables grow unbounded. Lab-safe; production needs ILM (30/90d) + disk alerts at 75/85%.
3. **No SLA/escalation paging**: HIGH risk only notifies Discord/Gmail; no on-call page, no ack deadlines, no MTTR metrics.
4. **Report + decision endpoints**: functional, but single shared secret (no RBAC, no per-analyst audit identity beyond note text).
5. **TI coverage**: VirusTotal (IP/file/URL) + AbuseIPDB only; no URLhaus/OTX/commercial feeds. Free-tier quotas (VT 4/min) → cache 24h/12h mitigates bursts, not sustained load.
6. **AI layer**: free-tier models (503/429 common) → deterministic fallback covers outage, but inference quality varies; MITRE/confidence are model-narrated, not verified.
7. **Coverage**: no C2-beaconing (needs NetFlow/DNS), no lateral-movement graph, no Windows host/EDR real source, no mail-infra (blast radius manual), no DLP/IdP (impossible-travel/MFA).
8. **Secrets**: n8n credentials + manager key file; VT key was exposed in chat once → ROTATE before public demo. No vault/KMS.
9. **Single-box failure domains**: n8n VPS reboot kills automation; manager reboot kills detection (observed). No HA.
10. **Adversarial robustness**: no webhook replay protection (nonce/timestamp), no alert signing; assume trusted network (Tailscale/private).
