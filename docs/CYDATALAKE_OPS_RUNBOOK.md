# CyDataLake Ops Runbook — Manual Steps Required

Everything in this document is a **manual action for a human with server/vendor-console access** —
none of it was performed as part of building the CyDataLake code (Phases 0-5), because each item is
either real infrastructure provisioning, a production-affecting restart, or requires credentials
this session never had. Companion to `docs/CYDATALAKE_MIGRATION_PLAN.md` (architecture/status) and
`docs/SIEM_PROXY_AUDIT.md` (Phase 5 route audit).

Cy360 is bare-metal, no Docker (`feedback_no_docker` convention) — every step below is systemd +
native packages, not containers.

**§1-3 (Kafka/ClickHouse/ingest worker) are now automated** — `cycentra-setup.sh` has an optional
interactive step ("CYDATALAKE (KAFKA + CLICKHOUSE) — OPTIONAL", inserted after the SYSTEMD SERVICES
step, before nginx vhosts). It defaults to **No** and is fully idempotent — safe to answer yes on a
re-run. It installs Kafka (KRaft, single broker), creates all 8 topics, installs ClickHouse, sets a
generated ClickHouse password, patches `KAFKA_ENABLED`/`CLICKHOUSE_ENABLED`/connection vars into
`/opt/cycentra/.env`, deploys the `cydatalake-ingest-worker` systemd service, and restarts the Flask
backend to pick up the new env vars. Sections §1-3 below are kept as the manual/troubleshooting
reference for what that automation does under the hood — use them if the installer step fails
partway, not as the primary path. **§4 (vendor credentials) has no automation** — that's inherently
a human-with-console-access task per vendor.

**Wazuh/CySIEM is now an optional installer prompt (v1.0.211)**, not mandatory — `cycentra-setup.sh`
asks "Install CySIEM (Wazuh-based SIEM engine)?" defaulting to **yes** (existing behavior preserved
for existing deployments; only a fresh full install can answer no). See
`docs/CYDATALAKE_MIGRATION_PLAN.md` §3 for exactly what's skipped when the answer is no, and read the
coverage-gap warning there before recommending "no" for any production client — CyEDR + CyCollector's
Sigma engine (3 rules by default) + the connectors in §4 below do not yet match Wazuh's detection
breadth.

**Before any of this reaches a real server — a step this document previously omitted:** none of the
new Python (`cysiemstack/connectors/`, `connector_bridge.py`, `dedup.py`, `clickhouse_store.py`,
`ingest_worker.py`, `detection/`) or the new `blueprints/connectors/routes.py` blueprint exists on any
server yet. `cycentra-setup.sh`'s `pip3 install` step installs a pre-built `cycentra_backend` wheel
resolved from a GitHub Release (or a local bundle) — it does **not** read from this git checkout
directly. **A new release has to be cut (new wheel built and published via this project's existing
CI/release process) before re-running the installer would deploy any of this CyDataLake code at
all**, regardless of whether Kafka/ClickHouse are installed. Same for the portal: the new
`portal/src/pages/connectors/index.jsx` page needs `npm run build` and a deploy before it shows up in
the sidebar (`docs/RELEASE_NOTES.md`/`CLAUDE.md` deploy notes — no Docker, `npm run build` +
`systemctl restart cycentra-backend.service`).

## 0. What's actually left to reach full end-to-end testing

In order:
1. **Cut a release** containing this session's backend changes (however this project's CI publishes
   the `cycentra_backend` wheel today) so the server-side `pip3 install` step in `cycentra-setup.sh`
   has something new to install.
2. **`npm run build`** the portal so `connectors/index.jsx` is actually served.
3. Re-run `cycentra-setup.sh` in `update` mode on the target server, answering **yes** to the new
   CyDataLake prompt.
4. Configure at least one connector with real credentials (§4 below — Wazuh recommended first).
5. **Then** the actual end-to-end test, concretely:
   - `journalctl -u cydatalake-ingest-worker -f` — confirm "CyDataLake ingest worker started", no
     Kafka/ClickHouse connection errors.
   - `/opt/kafka/bin/kafka-console-consumer.sh --topic raw.<vendor> --bootstrap-server 127.0.0.1:9092` —
     confirm real events arriving after a connector pull or CyCollector agent activity.
   - `clickhouse-client --query "SELECT count() FROM cydatalake.raw_events"` — confirm rows landing
     in the hot store.
   - Cy360 portal Alert Feed — confirm the same event shows up there too (via the existing Redis/
     correlation-engine path, independent of the Kafka/ClickHouse path).
   - Feed a log line matching one of the 3 Sigma starter rules (e.g. a real `Failed password` SSH
     line) through a CyCollector agent — confirm it lands as rule_id 101150-101153 (not the flat
     101100 bucket) with the matched rule's severity.
   - Trigger the same underlying alert from two sources at once (e.g. enable `WazuhConnector` against
     a cluster that's already flowing through the file-tail) — confirm `dedup.py` logs "suppressed N
     duplicate" and only one copy reaches the Alert Feed.

---

## 1. Provision Kafka (single-broker KRaft mode)

Needed to turn on Phase 2 (`KAFKA_ENABLED=true`). Do this on the Cy360 server.

```bash
ssh -p 2026 root@<cy360-server-ip>

# 1. Install a JDK (Kafka requires Java 11+)
apt-get update && apt-get install -y openjdk-17-jre-headless

# 2. Download and unpack Kafka (pick the latest 3.x release)
cd /opt
curl -L -o kafka.tgz https://downloads.apache.org/kafka/3.7.0/kafka_2.13-3.7.0.tgz
tar -xzf kafka.tgz && mv kafka_2.13-3.7.0 kafka && rm kafka.tgz

# 3. Generate a cluster ID and format storage for KRaft (no ZooKeeper needed)
cd /opt/kafka
KAFKA_CLUSTER_ID=$(bin/kafka-storage.sh random-uuid)
bin/kafka-storage.sh format -t "$KAFKA_CLUSTER_ID" -c config/kraft/server.properties

# 4. Edit config/kraft/server.properties — set these at minimum:
#    listeners=PLAINTEXT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093
#    advertised.listeners=PLAINTEXT://127.0.0.1:9092
#    log.dirs=/var/lib/kafka-logs
#    (leave everything else at KRaft defaults for a single-broker setup)

mkdir -p /var/lib/kafka-logs
```

Create the systemd unit:

```ini
# /etc/systemd/system/kafka.service
[Unit]
Description=Apache Kafka (KRaft, single broker)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/kraft/server.properties
ExecStop=/opt/kafka/bin/kafka-server-stop.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now kafka
systemctl status kafka   # confirm it's running before proceeding

# Create the 8 topics CyDataLake publishes to
for t in raw.syslog raw.edr raw.network raw.audit raw.splunk raw.qradar raw.sentinelone raw.paloalto; do
  /opt/kafka/bin/kafka-topics.sh --create --topic "$t" --bootstrap-server 127.0.0.1:9092 \
    --partitions 3 --replication-factor 1
done
```

Then, in `/opt/cycentra/.env`:

```
KAFKA_ENABLED=true
KAFKA_BROKERS=127.0.0.1:9092
```

```bash
systemctl restart cycentra-backend.service
```

**Verify:** `journalctl -u cycentra-backend -f` should show no Kafka connection errors on the next
collector/EDR/connector event. `bin/kafka-console-consumer.sh --topic raw.syslog --bootstrap-server
127.0.0.1:9092 --from-beginning` should show JSON events once CyCollector agents are running.

---

## 2. Provision ClickHouse

Needed to turn on Phase 4 (`CLICKHOUSE_ENABLED=true`) and the ingest worker.

```bash
ssh -p 2026 root@<cy360-server-ip>

curl https://clickhouse.com/ | sh
mv clickhouse /usr/local/bin/
clickhouse install   # creates clickhouse-server systemd service + default config

systemctl enable --now clickhouse-server
systemctl status clickhouse-server
```

The `cydatalake` database and `raw_events` table are created automatically by
`cysiemstack/clickhouse_store.py` on first connection — no manual schema step needed once the
ingest worker starts.

In `/opt/cycentra/.env` (or a dedicated env file for the ingest worker — see step 3):

```
CLICKHOUSE_ENABLED=true
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=<set one — do not leave the default empty password in production>
```

Set a password: `clickhouse-client --query "ALTER USER default IDENTIFIED BY '<password>'"` (do
this once, immediately after install, before exposing port 8123 to anything).

---

## 3. Deploy the ingest worker

The ingest worker (`backend/cysiemstack/ingest_worker.py`) is a standalone process — it does **not**
run inside gunicorn/Flask.

```bash
# On the server, from the deployed backend directory (wherever app.py lives — check
# systemd's cycentra-backend.service WorkingDirectory for the exact path)
scp backend/cysiemstack/ingest_worker.py root@<cy360-server-ip>:/usr/local/lib/python3.12/dist-packages/cysiemstack/
scp backend/cysiemstack/clickhouse_store.py root@<cy360-server-ip>:/usr/local/lib/python3.12/dist-packages/cysiemstack/
scp backend/cysiemstack/kafka_bridge.py root@<cy360-server-ip>:/usr/local/lib/python3.12/dist-packages/cysiemstack/
# (adjust the dist-packages path to match this server's actual deploy path — see
# reference_cymind_server memory for the pattern used elsewhere in this project)

pip3 install kafka-python clickhouse-connect pyarrow
```

```ini
# /etc/systemd/system/cydatalake-ingest-worker.service
[Unit]
Description=CyDataLake Kafka-to-ClickHouse ingest worker
After=network.target kafka.service clickhouse-server.service

[Service]
Type=simple
User=root
EnvironmentFile=/opt/cycentra/.env
WorkingDirectory=/usr/local/lib/python3.12/dist-packages
ExecStart=/usr/bin/python3 -m cysiemstack.ingest_worker
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now cydatalake-ingest-worker
journalctl -u cydatalake-ingest-worker -f   # confirm "CyDataLake ingest worker started" with no errors
```

If either `KAFKA_ENABLED` or `CLICKHOUSE_ENABLED` is still `false`, the worker starts and idles —
safe to deploy ahead of finishing steps 1/2.

---

## 4. Obtain vendor credentials and configure connectors

Once a connector is configured, `blueprints/connectors/routes.py` polls it automatically via the
scheduler dispatcher — no further manual step needed per-connector after this.

**Where to configure:** Cy360 portal → sidebar → **CyDataLake → SIEM Connectors** (new page,
`portal/src/pages/connectors/index.jsx`) → **+ Add Connector**.

### Wazuh (recommended first pilot — no field-mapping translation needed)
1. Find the Wazuh **indexer** (OpenSearch) host — not the Wazuh Manager (`WAZUH_API_URL`). Usually
   port 9200 on the same box or cluster running the Wazuh dashboard.
2. Use an existing indexer read user, or create one:
   `curl -k -u admin:<admin-password> -X PUT https://<indexer>:9200/_plugins/_security/api/internalusers/cydatalake -H 'Content-Type: application/json' -d '{"password": "<new-password>", "backend_roles": ["readall"]}'`
3. In the Connectors UI: vendor=Wazuh, base_url=`https://<indexer>:9200`, username=`cydatalake`,
   password=`<new-password>`, index_pattern=`wazuh-alerts-*` (default).
4. Click **Test**, then **Pull Now** to confirm events land in the Alert Feed.
5. **Before enabling continuous polling**, confirm whether this Wazuh cluster's alerts are already
   flowing in via the existing `cysiem_to_redis.py` file-tail — if so, read
   `docs/CYDATALAKE_MIGRATION_PLAN.md` §7's dual-path dedup caveat before turning this on for that
   same cluster.

### Splunk
1. Splunk Web → Settings → Tokens → **New Token**. Requires token auth enabled
   (`server.conf` → `[general] allowRemoteLogin` / token auth is on by default in modern Splunk).
2. Note the management port (default 8089, not the web UI's 8000).
3. In the Connectors UI: vendor=Splunk, base_url=`https://<splunk-host>:8089`,
   api_token=`<token>`, search_query=`search index=notable` (or your own SPL if not using ES).

### QRadar
1. QRadar Console → Admin → **Authorized Services** → **Add Authorized Service** → note the
   generated token (this is the `SEC` header value).
2. Confirm the deployment's QRadar version to set `api_version` correctly (Admin → System
   Information).
3. In the Connectors UI: vendor=QRadar, base_url=`https://<qradar-console>`, sec_token=`<token>`.

### SentinelOne
1. S1 Management Console → Settings → **API Tokens** → **Generate API Token** (scope it to the
   narrowest role that can read Threats).
2. Find your tenant's API base URL (Console → Support → API Doc, or it matches your login URL).
3. In the Connectors UI: vendor=SentinelOne, base_url=`https://<tenant>.sentinelone.net`,
   api_token=`<token>`.

### Palo Alto Cortex XDR/XSIAM
1. Cortex console → Settings → **API Keys** → **New Key**. Use **Advanced** key type (not
   Standard) — this connector implements the Advanced auth scheme specifically.
2. Note both the **Key ID** and the **Key** (secret) — the secret is shown only once.
3. In the Connectors UI: vendor=Palo Alto, base_url=`https://api-<tenant>.xdr.<region>.paloaltonetworks.com`
   (get the exact base URL from the console's API docs page — it varies by tenant/region/product),
   api_key_id=`<Key ID>`, api_key=`<Key secret>`.
4. **This connector is the least likely to work on the first try** (see migration doc §7) — if
   `Test` fails, double check the base URL path and whether your tenant is XDR vs. XSIAM (they use
   slightly different API paths); this may need a one-line fix to `paloalto_connector.py`'s
   endpoint path once you have real error responses to look at.

### Office 365 (Management Activity API) — v1.0.211
1. Azure Portal → **App registrations** → **New registration**. Grant **Application permission**
   `ActivityFeed.Read` (Office 365 Management APIs) and click **Grant admin consent**.
2. Create a client secret under **Certificates & secrets** — note it immediately, shown once.
3. In the Connectors UI: vendor=Office 365, tenant_id=`<Directory (tenant) ID>`,
   client_id=`<Application (client) ID>`, client_secret=`<secret>`, content_types left blank for all.
4. First `Pull Now` will subscribe to each content type automatically — this can take a few minutes
   to start returning content on a brand-new tenant subscription (Microsoft's own propagation delay,
   not a connector issue).

### Azure AD / Entra ID — v1.0.211
1. Same app registration as O365 above works, or a dedicated one — grant **Application permissions**
   `AuditLog.Read.All` + `Directory.Read.All` (Microsoft Graph), grant admin consent.
2. In the Connectors UI: vendor=Azure, tenant_id/client_id/client_secret as above.

### AWS CloudTrail — v1.0.211
1. IAM → create a user (or role, if adapting the connector for STS later) with an inline policy
   granting only `cloudtrail:LookupEvents` (read-only, narrowest scope).
2. Generate an access key for that user.
3. In the Connectors UI: vendor=AWS, access_key_id/secret_access_key, region=`<e.g. us-east-1>`.
4. Requires `boto3` installed on the server (`pip3 install boto3` — already in `requirements.txt` as
   of v1.0.211, picked up on the next backend package release).

### GCP Cloud Audit Logs — v1.0.211
1. GCP Console → IAM & Admin → **Service Accounts** → create one, grant **roles/logging.viewer**.
2. Create a JSON key for that service account and download it.
3. In the Connectors UI: vendor=GCP, project_id=`<project ID>`, service_account_json=paste the
   **entire contents** of the downloaded JSON key file.
4. Requires `google-cloud-logging` installed on the server (`pip3 install google-cloud-logging` —
   already in `requirements.txt` as of v1.0.211).

### Enabling Sigma matching for cloud connector events (optional, off by default)
The four cloud connectors above check for a real Sigma rule match before falling back to their own
heuristic severity guess — but this is gated behind `SIGMA_IMPORTED_RULES_ENABLED=false` (default)
because testing surfaced real false-positive risk from short-value substring collisions (see
`docs/CYDATALAKE_MIGRATION_PLAN.md` §4/§12 for the specifics — this isn't a caveat to skim past).
**Do not set this to `true` in production** until that gap is closed. If you want to experiment with
it in a non-production environment: set `SIGMA_IMPORTED_RULES_ENABLED=true` in `/opt/cycentra/.env`
and restart `cycentra-backend`, then watch the Alert Feed closely for matches that don't make sense
for the underlying event — that's the false-positive pattern to look for.

---

## 5. Cutover checklist (Phase 6) — do not start until Phases 4-5 are actually done

This is sequencing guidance, not something to execute today — nothing above constitutes "done"
until each step has run against real traffic for an agreed burn-in period.

- [ ] Step 1-4 above complete and stable for 2+ weeks with real vendor tenants.
- [ ] Phase 4's cross-source dedup (`cysiemstack/dedup.py`) confirmed effective — check
      `journalctl` for "suppressed N duplicate" log lines and spot-check they're correct
      suppressions, not false positives.
- [ ] Phase 5's audit (`docs/SIEM_PROXY_AUDIT.md`) turned into actual PRs, reviewed and merged one
      capability at a time — ingestion-adjacent routes first, fleet enroll/remove last.
- [ ] For each Wazuh-Manager-API route retired: confirm the replacement (ITAM, CyEDR, or a rebuilt
      CyDataLake-native equivalent) has been running in parallel and produces equivalent output for
      at least the same 2-week window.
- [ ] Only then: per-deployment decision on whether to keep Wazuh Manager (fleet mgmt) running
      alongside its alerts now flowing through `WazuhConnector`, or retire it entirely for that
      deployment. This is a per-customer/per-environment decision, not a global switch.
