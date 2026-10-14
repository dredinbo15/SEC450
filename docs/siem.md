# Pushing SEC450 reports to Wazuh (DD-17)

The collector sends every new report to a Wazuh manager as one JSON line over
TCP syslog. Wazuh turns it into an alert, and analysts see it in the Wazuh
dashboard. The dashboard is reached from anywhere through a Cloudflare tunnel
that sits behind Cloudflare Access, so this host publishes no ports.

```
SEC450 collector ──JSON over TCP 514──▶ wazuh.manager ──▶ wazuh.indexer ──▶ wazuh.dashboard
        private Docker network "siem" (172.30.0.0/24)                          │
                                                                                ▼
browser ──▶ siem.<domain> ──▶ Cloudflare Access (login) ──▶ tunnel "siem" ──▶ dashboard (Wazuh login)
```

## What is sent

One line per report, at most `siem.batch_size` per cycle:

| Field | Meaning |
|---|---|
| `srcip` | Requester IP (Wazuh's static field, so its GeoIP enrichment works) |
| `sec450.report_id`, `cluster_id`, `previous_cluster_id` | Report and cluster ids; a follow-up cluster links to the one before it |
| `sec450.severity`, `rule.id`, `rule.name` | The rule's verdict, which sets the Wazuh level |
| `sec450.summary` | One-line summary, used as the alert description |
| `sec450.usernames`, `country`, `asn`, `event_count`, `window_start`, `window_end`, `bytes_sent` | Who, where from, how much |
| `sec450.ai.*` | The advisory AI assessment (status, classification, recommended severity, model) |
| `sec450.integrity`, `collection_gaps` | Hash-chain status and how many collection gaps overlap the report |
| `sec450.report_url` | Link to the full report on the API (needs an API key) |

Raw log lines and the full timeline are **not** sent; they stay behind the
authenticated, audited API (DD-10, DD-12).

Delivery is at-least-once: a report is recorded in `siem_delivery` only after
the send succeeds, so if Wazuh is down the reports wait and go out on a later
cycle. Existing reports are sent on the first cycle after the feature is turned on.

## Alert levels

[deploy/wazuh/sec450_rules.xml](../deploy/wazuh/sec450_rules.xml):

| SEC450 severity | Wazuh rule | Level |
|---|---|---|
| low (or missing) | 100450 | 3 |
| medium | 100451 | 7 |
| high | 100452 | 10 |
| critical | 100453 | 13 |

In the dashboard, filter on `rule.groups: sec450` or `rule.id: 10045*`.

## Wazuh deployment

Based on the official single-node Docker deployment
(`git clone --branch v4.14.7 https://github.com/wazuh/wazuh-docker`), with these changes.
Avoid a release published in the last couple of weeks: the 4.14.9 images shipped with
empty service scripts and the manager never started.

1. **Passwords.** Generate new ones for `admin`, `kibanaserver` and `wazuh-wui`,
   put them in `single-node/.env` (`chmod 600`) as `INDEXER_PASSWORD`,
   `DASHBOARD_PASSWORD` and `API_PASSWORD`, put their bcrypt hashes in
   `config/wazuh_indexer/internal_users.yml`, delete the demo users there
   (their passwords are public), and set the API password in
   `config/wazuh_dashboard/wazuh.yml`. Do this **before the first start**: the
   indexer loads users from that file only once.
2. **No published ports.** Remove every `ports:` entry. Nothing on the host or
   the LAN can reach Wazuh directly.
3. **The `siem` network.** Attach `wazuh.manager` to a network named `siem`
   with subnet `172.30.0.0/24`.
4. **Syslog input** in `config/wazuh_cluster/wazuh_manager.conf`, after the
   existing `<remote>` block:
   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>tcp</protocol>
     <allowed-ips>172.30.0.0/24</allowed-ips>
   </remote>
   ```
5. **Rules.** Copy `deploy/wazuh/sec450_rules.xml` to
   `config/sec450/` and mount it at `/wazuh-config-mount/etc/rules/sec450_rules.xml`
   on the manager.
6. **Tunnel.** A `cloudflared` service on the default network, pointing at
   `https://wazuh.dashboard:5601` (see below).

Then generate certificates and start:

```sh
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

## Turning it on in SEC450

Start Wazuh first (it creates the `siem` network). Then, in SEC450:

```sh
# .env
COMPOSE_FILE=docker-compose.yml:docker-compose.siem.yml
```
```yaml
# config.yaml
siem:
  enabled: true
  host: wazuh.manager
  port: 514
  report_url: https://seclog.<domain>/v1/reports/
```
```sh
docker compose up -d collector
docker compose logs collector | grep -i siem     # "forwarded N reports to the SIEM"
```

## Remote access to the dashboard

1. **Cloudflare Access first.** In Cloudflare Zero Trust → Access →
   Applications → Add an application → Self-hosted: application domain
   `siem.<domain>`, and a policy that allows only named emails (one-time PIN
   or an identity provider). Without this the dashboard would be public.
2. **Tunnel and route** (on the host that holds `~/.cloudflared/cert.pem`):
   ```sh
   cloudflared tunnel create siem
   cp ~/.cloudflared/<uuid>.json single-node/secrets/cloudflared.json   # chmod 644
   cloudflared tunnel route dns siem siem.<domain>
   ```
3. `single-node/config/cloudflared/config.yml`:
   ```yaml
   tunnel: <uuid>
   credentials-file: /etc/cloudflared/credentials.json
   ingress:
     - hostname: siem.<domain>
       service: https://wazuh.dashboard:5601
       originRequest:
         originServerName: wazuh.dashboard
         caPool: /etc/cloudflared/root-ca.pem
     - service: http_status:404
   ```
   `root-ca.pem` is the deployment's public CA certificate, copied readable
   to `config/cloudflared/`, so the tunnel verifies the dashboard's certificate.
4. `docker compose up -d cloudflared`, then browse to `https://siem.<domain>`:
   Cloudflare's login first, then Wazuh's (`admin` / `INDEXER_PASSWORD`).
