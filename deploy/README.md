# Deployment guide

How to rebuild the whole stack from this repo on a fresh Ubuntu VPS.

## 1. Prerequisites

- Ubuntu 22.04/24.04, 2 GB+ RAM recommended (nodes: n8n + Postgres only; Wazuh ran on a separate VM).
- Docker + Docker Compose plugin.
- A Discord webhook URL and a Gmail account/app-password for notifications.

## 2. Bring up n8n + Postgres

```bash
sudo mkdir -p /opt/soc-n8n && sudo cp deploy/docker-compose.yml /opt/soc-n8n/
cd /opt/soc-n8n
# create an .env next to docker-compose.yml (do not commit it):
#   POSTGRES_PASSWORD=<strong password>
#   N8N_ENCRYPTION_KEY=<random 32+ chars>: openssl rand -hex 32
sudo docker compose up -d
```

n8n listens on `127.0.0.1:5678` only (see `ports:`). Put any reverse proxy/auth in front of it.

## 3. Import workflows

```bash
# from the repo root
for id in 01_SOC_Alert_Intake 02_SOC_Decision 03_SOC_Report \
          04_SOC_Enrichment 05_SOC_AIAnalysis 06_SOC_DLQ 07_SOC_AutoClose; do
  WFILE="workflows/${id}.json"
  sudo docker exec -i soc-n8n-n8n-1 n8n import:workflow --input=/dev/stdin < "$WFILE"
done
# activate each (import leaves them inactive), then restart the container once:
sudo docker exec soc-n8n-n8n-1 n8n update:workflow --id=<ID> --active=true   # repeat per workflow
sudo docker compose restart
```

Node names/IDs inside the JSON files are stable; the webhook paths below stay valid.

## 4. Recreate credentials inside n8n (UI)

The repo JSONs contain placeholders, not secrets. Recreate in the n8n UI:

- Header Auth `X-OTX-API-KEY` (OTX), header `Auth-Key` (URLhaus), `Key` (AbuseIPDB)
- OpenRouter API key
- n8n Postgres credential for the workflow SQL nodes

## 5. Endpoints (localhost only)

| Endpoint | Purpose |
|---|---|
| `POST /webhook/soc-ingest` | alert intake (headers `X-SOC-Key`, `X-SOC-TS`) |
| `POST /webhook/soc-autoclose` | manual/auto close sweep (header `X-SOC-Key`) |
| `GET /webhook/soc-report?incident_id=...` | full report page |
| `POST /webhook/soc-decision` | analyst decision (ingest key + analyst token) |

## 6. Optional: CloudTrail poller

`tests/tools/soc_cloudtrail.py` polls AWS management events into the ingest webhook
(cron `*/5`, root). If you use it, put AWS creds in `/root/.aws` or the script env —
never inside the repo. `/root/soc-key` on the original box stored the ingest key.

## 7. Notes

- `$env` access is denied on this n8n instance; the Discord embed node in
  `workflows/01` carries a placeholder — paste a real webhook URL in the UI after import.
- Import = deactivate; always re-activate + restart once after a fresh import.
- DB name in the compose file is `n8n`; workflow SQL targets the `soc` database —
  create it (`CREATE DATABASE soc;`) and adjust `DB_POSTGRESDB_DATABASE` if needed.
