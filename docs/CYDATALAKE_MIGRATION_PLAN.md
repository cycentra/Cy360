# CyDataLake Migration Plan — Multi-Vendor SIEM Aggregation for Cy360

**Status (v1.0.212):** All 7 phases now have either shipped code or a completed analysis artifact —
see the per-phase sections below. **None of Phases 2-4 have been run against real infrastructure or
live vendor tenants** — Kafka/ClickHouse are not provisioned anywhere by default (an *optional*
installer step now exists, see §5.5), and no connector has touched a real Splunk/QRadar/SentinelOne/
Cortex/Wazuh-indexer/O365/Azure/AWS/GCP tenant. Phase 5 is analysis-only by design (§9). Phase 6
cannot start until 2-4 are proven with real traffic. **`docs/CYDATALAKE_OPS_RUNBOOK.md`** covers every
manual infrastructure/credential step; **`docs/SIEM_PROXY_AUDIT.md`** covers the Phase 5 route audit.

**v1.0.213 update — the structural false-positive risk described below is now fixed, and the corpus
is loaded by default.** §4/§14 below describe the *original* haystack/substring matcher and why it was
kept opt-in; that matcher has been replaced with real per-field lookup + `logsource` product/category/
service routing (see "v1.0.213 update" near the end of §4 for what changed and why it was judged safe
to flip on), and the corpus itself grew from 279 to ~3,739 rules (SigmaHQ's `rules/` +
`rules-emerging-threats/` + `rules-threat-hunting/`). `SIGMA_IMPORTED_RULES_ENABLED` still exists but
now defaults to `true` and functions as an emergency rollback switch, not the normal control path.
Read the rest of this section for the history of *why* the original design was cautious — that
reasoning is still correct about the old matcher, just no longer describes the current one.

**Owner:** g-cyra-360 (backend/agent), coordinate with g-cyra-devops before any infra (Kafka/
ClickHouse) work.
**Audience:** this document is written so a development agent picking up this work cold does not
need to re-derive architecture decisions already made. Read this fully before writing code.

---

## Master Status Table

Legend: ✅ Done/shipped-and-verified · ⚠️ Shipped, not verified against real infra/tenants ·
🔒 Shipped, opt-in and disabled by default · ⛔ Not started · 🚫 Deliberately not attempted (see reason)

| # | Phase / Task | Key component(s) | Status | Version | Next step / planned future task |
|---|---|---|---|---|---|
| 0 | Detection-engine decision | Sigma-rule-subset engine (`sigma_engine.py`) | ✅ Decided + implemented | v1.0.210 | Grow past 3 starter rules with real CyCollector traffic |
| 0 | Sigma community rule bulk-import | `import_sigma_rules.py`, ~3,739 rules in `rules/imported/` | ✅ On by default (`SIGMA_IMPORTED_RULES_ENABLED=true`, kill switch only) | v1.0.213 | Watch rule IDs 101150-101153/101380-101383 in the Alert Feed against first real production traffic |
| 1 | CyCollector agent (raw log collection) | `collector_bp`, `collector_bridge.py`, `agent/cycollector_agent.py` | ✅ Shipped | v1.0.207 | Portal UI for agent fleet visibility (not built yet) |
| 2 | Kafka bus (producer side) | `kafka_bridge.py`, `KAFKA_ENABLED` | ⚠️ Code shipped, no broker provisioned | v1.0.208 | Provision broker (installer step exists, opt-in — see row 2b) |
| 2b | Kafka + ClickHouse installer automation | `cycentra-setup.sh` `_INSTALL_CYDATALAKE` step | 🔒 Opt-in installer prompt (default no) | v1.0.211 | Run it on a real server; currently untested end-to-end |
| 3 | Wazuh connector (indexer pull) | `wazuh_connector.py` | ⚠️ Shipped, unverified | v1.0.209 | Test against a live Wazuh indexer; resolve dual-path dedup question (§14) |
| 3 | Splunk / QRadar / SentinelOne / Cortex connectors | `connectors/{splunk,qradar,sentinelone,paloalto}_connector.py` | ⚠️ Shipped, unverified | v1.0.209 | Needs a pilot tenant per vendor — see per-vendor risk notes (§7) |
| 3 | Cloud connectors (O365 / Azure / AWS / GCP) | `connectors/{office365,azure,aws,gcp}_connector.py` | ⚠️ Shipped, unverified | v1.0.212 | Needs a pilot tenant per vendor (ops runbook §4 has credential steps) |
| 3 | Connector CRUD API + scheduler | `blueprints/connectors/routes.py` | ✅ Shipped | v1.0.209 | — |
| 3 | Connector management UI | `portal/src/pages/connectors/index.jsx` | ⚠️ Shipped, not built/browser-tested | v1.0.210 | `npm run build` + deploy; exercise in a browser |
| 3 | Wazuh/CySIEM optional at install | `cycentra-setup.sh` `_INSTALL_CYSIEM` | ✅ Shipped | v1.0.211 | None — default stays "yes" until coverage gap (§3) is closed |
| 4 | Cross-source dedup | `dedup.py` | ⚠️ Shipped, never seen real duplicate traffic | v1.0.210 | Validate against a real Wazuh dual-path or multi-vendor duplicate case |
| 4 | ClickHouse hot store | `clickhouse_store.py` | ⚠️ Shipped, no server provisioned | v1.0.210 | Provision ClickHouse (row 2b); verify `query_arrow()` cold-export path |
| 4 | Standalone ingest worker | `ingest_worker.py` (own systemd unit) | ⚠️ Shipped, never run against real data | v1.0.210 | Deploy + observe against real Kafka/ClickHouse traffic |
| 5 | Wazuh-Manager-API route audit | `docs/SIEM_PROXY_AUDIT.md` | ✅ Audit complete (analysis only) | v1.0.210 | Turn findings into PRs, ingestion-adjacent routes first (§9) |
| 5 | `siem_proxy.py` rewrite itself | `backend/siem_proxy.py` | 🚫 Deliberately not attempted | — | Highest blast radius — needs a live Wazuh Manager to test against first |
| 6 | Phased cutover | — | ⛔ Not started | — | Cannot start until Phases 2-5 are proven with real traffic (§10) |
| — | Storage-centralization question (GRC/EDR/ITAM → data lake) | Postgres `correlation` DB vs. ClickHouse | ✅ Answered (recommend against wholesale move) | advisory only, no code | Revisit only if cross-module BI/reporting becomes a real requirement |

---

## 0. Architecture reframe (read this first — it changed after Phase 2)

The original framing of this document was "replace Wazuh." **That framing is superseded.** The
actual goal, as of this revision: build CyDataLake as a **vendor-agnostic aggregation and
correlation layer** that pulls from multiple existing SIEM/EDR platforms — Wazuh, Splunk, QRadar,
Palo Alto Cortex XDR/XSIAM, SentinelOne — plus CyCollector's own raw host-log collection for
sources that don't have a SIEM of their own. Wazuh becomes **one connector among several**, not the
thing being torn out.

This materially changes Phase 0's risk profile: for every vendor-fed source, detection already
happened at the vendor (Splunk notable events, QRadar offenses, Cortex incidents, SentinelOne
threats are all post-detection artifacts) — CyDataLake does not need to re-implement a decoder/rule
engine for them. The from-scratch detection-engine problem is now scoped down to **only**
CyCollector's raw generic logs (journald/syslog/oslog/Windows Event Log with no vendor SIEM behind
them) — see §5.

## 1. Goal

```
CySIEM/EDR/Cloud sources ──▶ CyCollector ─┐
Wazuh / Splunk / QRadar /                 ├──▶ Kafka ──▶ CyDataLake ──▶ Cy360
SentinelOne / Cortex XDR ──▶ Connectors ──┘
```

Aggregate every source into one correlation/search/reporting plane in Cy360, without requiring
every customer to rip out whatever SIEM/EDR they already run. CyCollector remains the answer for
hosts/sources that have no SIEM of their own.

## 2. Target Architecture

```
[Vendor SIEMs: Wazuh, Splunk, QRadar, SentinelOne, Cortex XDR/XSIAM]
        │  pull, on a schedule, via cysiemstack/connectors/*
        ▼
                                            [CyCollector agents: hosts w/ no SIEM]
                                                    │  push, via HTTP
                                                    ▼
   siem_connectors polling ──publish──▶  Kafka (raw.syslog, raw.edr, raw.splunk,
   (blueprints/connectors)                        raw.qradar, raw.sentinelone, raw.paloalto)
                                                    │
                                                    ▼
                                     CyDataLake ingest workers  (Phase 4 — NOT STARTED)
                                     (decode/detect only for raw.syslog; everything
                                      else is already-detected, just normalize)
                                                    │
                     ┌──────────────────────────────┼───────────────────────┐
                     ▼                              ▼                       ▼
              Hot store (search/hunt)        Cold store (compliance)   Correlation engine
                                                                        (existing ingestor.py/
                                                                         grouper.py — reused
                                                                         almost unchanged)
                                                                                │
                                                                                ▼
                                                                       Postgres alerts/incidents
                                                                                │
                                                                                ▼
                                                                            Cy360 portal
```

**Key finding that shapes every phase below:** the correlation engine (`ingestor.py` →
`normaliser.py` → `grouper.py`/`correlator.py`) is already source-agnostic. It doesn't care where
alerts come from — CyEDR proved this in production by wrapping its own telemetry into a synthetic
Wazuh-shaped envelope and pushing it onto the same Redis list Wazuh's `alerts.json` feeds.
CyCollector (Phase 1) and the multi-vendor connectors (Phase 3) both extend that exact pattern
rather than inventing a new one — this is why Phase 3 shipped in one session instead of requiring
new correlation-engine work.

## 3. Current state — what Wazuh actually does today (still true, now just one input among several)

| Capability | Where it lives today | Status |
|---|---|---|
| Log/alert generation (decoders + ~30k OSSEC rules) | Wazuh Manager, on-box | Unchanged — Wazuh keeps doing its own detection; CyDataLake consumes the output via two parallel paths (see below) |
| Ingestion into Cy360 (push path) | `backend/cysiemstack/cysiem_to_redis.py` tails `/var/ossec/logs/alerts/alerts.json` → RPUSH into Redis `cysiemstack:alerts:raw`. Exists because Filebeat 7.x crashes with a seccomp SIGABRT on kernel 6.x — a real production scar. | Still running, unmodified |
| Ingestion into Cy360 (pull path, NEW) | `WazuhConnector` (`cysiemstack/connectors/wazuh_connector.py`) polls the Wazuh **indexer** (OpenSearch) `wazuh-alerts-*` index directly — a different mechanism from the file-tail above. | Shipped Phase 3, unverified against a live cluster; see §6 for the dedup caveat |
| Correlation/UEBA | `backend/cysiemstack/correlation_engine/{ingestor,normaliser,grouper,correlator}.py` → Postgres `alerts`/`incidents`. Already vendor-agnostic. | No change needed — reuse as-is |
| Fleet/host management | `backend/siem_proxy.py` — ~50 routes hitting the **Wazuh Manager API** directly: agent enroll/remove, syscollector inventory, SCA, vulnerability detection, agent groups, active-response, dashboard SSO launch. | Untouched — still Wazuh-specific; see Phase 5 |

### v1.0.212 — Wazuh/CySIEM is now optional at install time

`cycentra-setup.sh` previously installed Wazuh unconditionally in full-install mode — there was no
way to deploy Cy360 without it. It's now an `ask_yn` prompt (default **yes** — this only changes
behavior for a client who explicitly opts out; existing deployments are unaffected). Answering no
skips: the Wazuh installer itself, the `cysiem_to_redis` bridge (would otherwise be a permanently-
idle systemd service with nothing to tail), the `cysiem.${BASE_DOMAIN}` nginx vhost + its SSL cert
request. Everything else in the script already self-guarded on Wazuh file/service existence and
needed no changes. `_INSTALL_CYSIEM` is computed once (via `dpkg -l | grep wazuh-manager`, falling
back to the prompt only for a genuinely fresh full install) and is available in every MODE.

**Say yes to this prompt unless the client deployment plan already accounts for the real detection
gap that comes with saying no** — see the honest coverage answer in this document's own git history/
conversation record: without Wazuh, there is no FIM, no rootcheck, no SCA/CIS benchmarking, and the
built-in OSSEC ruleset is gone. CyEDR (endpoint), CyCollector's Sigma engine (§4 — 3 rules by
default), and the multi-vendor/cloud connectors (§7, this section) are what's left, and none of them
individually or collectively match Wazuh's out-of-the-box detection breadth yet.

## 4. Phase 0 — Detection-engine decision — ✅ DECIDED + IMPLEMENTED v1.0.210

Decision made: option 1 (Sigma-rule layer), implemented as a lightweight, self-contained
Sigma-YAML-subset matcher — **not** the `pysigma` library, which is a rule-*conversion* toolkit
(Sigma → a target query language) rather than something designed to evaluate a rule directly
against a Python event dict at runtime. Using it here would mean standing up a conversion backend
for a query language nothing runs; a small subset matcher does the actual job with less machinery.

| File | What it does |
|---|---|
| `backend/cysiemstack/detection/sigma_engine.py` | `SigmaEngine`/`SigmaRule` — loads YAML rules with the standard Sigma `detection:` block shape (named selections, `field|contains`/`startswith`/`endswith`/`re` modifiers, boolean `condition` expressions with `and`/`or`/`not`/parens, safely evaluated via a whitelisted-token check before `eval()`). No aggregation/count-over-time support — repeated single-event matches from the same host already cluster into one incident via the correlation engine's existing time-window grouping (`grouper.py`), so brute-force-style detections don't need it here. |
| `backend/cysiemstack/detection/rules/*.yml` | 3 starter rules: SSH failed password (medium), sudo privilege escalation indicator (high), suspicious cron persistence — download-piped-to-shell (critical). **Functionally tested in this session** (not just AST-checked) against sample log lines — all 3 matched correctly, a benign line matched none. |
| `backend/cysiemstack/collector_bridge.py` | `_wrap_as_wazuh()` now runs every event through `get_engine().match()` first. A match upgrades rule_id/level/description to the matched rule's severity (rule_id **101150-101153**, see §11); no match falls back to the original flat 101100/low bucket. |

### v1.0.212 update — bulk-imported 279 real SigmaHQ rules, found and fixed a real bug, made the import opt-in

This session had live network access and used it: fetched 280 real rules directly from
github.com/SigmaHQ/sigma (cloud/aws, cloud/azure ×5 subcategories, cloud/gcp, cloud/m365 ×4,
identity/okta+duo+onelogin, linux/auditd, a 30-rule sample of windows/process_creation — ~1250 more
exist upstream, not yet pulled), tested them against the actual engine, and used the results to fix
real bugs rather than assume the engine worked:

- **Added Sigma's `1 of x*` / `all of x*` / `1 of them` / `all of them` selection-group syntax**
  (`SigmaRule._expand_wildcard_groups()`) — a real-data-driven addition: the *first* 135-rule sample
  was only 67% compatible before this, 100% after. This syntax appears in roughly a third of real
  Sigma rules.
- **Added support for list-valued selections** — Sigma allows a selection's value to be a list of
  maps (OR of AND-groups) or a bare list of strings (`keywords:` full-text search) — found via 4
  real rules that failed to load, both now handled.
- **Found and fixed a real logic bug**: `_expand_wildcard_groups` compared the captured quantifier
  string (`"all of"`) against the wrong literal (`"all"`), so **every `all of x*` group silently
  evaluated as OR instead of AND** — confirmed by a rule requiring 3 conditions matching a
  completely unrelated benign log line. This existed from the moment wildcard-group support was
  added until it was caught by testing against real rule content; it would never have been caught
  by the hand-written starter rules alone, none of which used this syntax.
- **Found a structural false-positive risk that is NOT a bug, and NOT fully fixed**: this engine
  matches against a flattened haystack (substring search), not real per-field structured lookup, and
  has no logsource-based rule routing. Short/common field values collide badly under substring
  search — e.g. a real rule keyed on `event_type_id: 3` matched an SSH log line purely because it
  contains the substring "3" (from an IP address), and a rule checking `userIdentity.type: Root`
  matched a `sudo` log line because it contains the word "root". **This is why the imported 279-rule
  corpus is opt-in (`SIGMA_IMPORTED_RULES_ENABLED=true`), not loaded by default** —
  `SigmaEngine(include_imported=False)` (the default) loads only the 3 hand-written starter rules,
  which were designed for and tested against this haystack-matching approach and don't have this
  short-value collision risk. See `sigma_engine.py`'s `SigmaEngine.__init__` docstring for the full
  reasoning.
- **4 rules were pulled out entirely** (moved to `rules_needs_configuration/`, outside what the
  engine loads at all) — they contain unfilled `<placeholder text>` values, a standard Sigma
  authoring convention meaning "fill this in for your environment before use." Loaded as-is, one of
  them matched almost every event tested against it.
- **Cloud connectors now check Sigma first**: `connector_bridge.py`'s office365/azure/aws/gcp
  normalizers call `get_engine().match_raw()` before falling back to their heuristic severity
  mapping — a real Sigma match (rule_id **101380-101383**, see §11) takes priority since it's a
  sourced detection, not a guess. This only fires when `SIGMA_IMPORTED_RULES_ENABLED=true`, for the
  same false-positive-risk reason above.
- New tool: `backend/cysiemstack/detection/import_sigma_rules.py` — filters a directory of upstream
  Sigma rules (aggregation rules and placeholder rules rejected, condition-compatibility verified
  against the actual engine) and copies compatible ones into `rules/imported/`. This is exactly the
  tool used to build the 279-rule corpus; re-run it against a full SigmaHQ clone to pull in the
  remaining ~970 rules or new upstream categories.
- Attribution: `rules/imported/ATTRIBUTION.md` — rules are DRL 1.1 licensed (permissive: commercial
  use/modification/redistribution allowed, attribution required). Author fields are preserved
  unmodified in every copied file, satisfying the license's attribution condition.

**Bottom line on Sigma (as of v1.0.212):** the infrastructure to bulk-adopt community rules is real and
works — the condition-parsing/loading side is solid (100% compatibility on the tested sample after the
fixes above). What's NOT solid yet is field-scoped matching precision at scale, which is exactly why the
279 rules are gated behind an explicit opt-in rather than silently active. Turning that flag on in
production without further engine work (real per-field structured matching, logsource-based rule
routing) risks the same class of false-positive-everywhere failure this session already found and
had to catch by hand.

### v1.0.213 update — root cause fixed (not worked around), corpus expanded to full SigmaHQ + emerging-threats + threat-hunting, opt-in flipped to on-by-default

Product owner decision: keep a kill switch (`SIGMA_IMPORTED_RULES_ENABLED`, now defaulting to `true`)
given Sigma-matched alerts feed the same auto-case-opening path as every other HIGH/CRITICAL alert, but
otherwise stop gating the corpus behind opt-in — and import the full upstream corpus rather than a
curated subset, since the number of source integrations is expected to grow from a handful to
hundreds/thousands over the near term and hand-curating rule-by-rule wouldn't scale with that.

What actually changed in `sigma_engine.py` to justify flipping the default (this is a real fix, not a
relaxed risk tolerance):
- **`SigmaRule.matches_logsource(hint)`** — parses each rule's `logsource:` block (product/category/
  service) and rejects evaluating a rule against an event whose bridge-supplied hint disagrees on any
  field both sides declare. `collector_bridge.py` derives the hint from `source_type`
  (journald/syslog→linux, oslog→macos, windows_eventlog→windows); `connector_bridge.py`'s
  `_sigma_envelope()` passes `{"product": vendor}`. `_PRODUCT_ALIASES` reconciles naming differences
  (SigmaHQ's rules use `m365`, this platform's connector is named `office365`, etc.). This alone stops
  an AWS-specific rule from ever being evaluated against a Windows event log line, closing the
  cross-category class of the "coincidental substring" bug.
- **`SigmaRule._lookup_field(root, field)`** replaced the flattened-haystack substring search entirely.
  It resolves the actual named field against the event's real structure — dotted-path lookup first
  (`userIdentity.type`), then a depth-limited recursive key search — and the default (no-modifier) Sigma
  match semantics were corrected from "contains" to real exact-match-with-wildcard (`fnmatch`), plus
  explicit `field: null` handling (absent-or-None). The `event_type_id: 3` / `userIdentity.type: Root`
  collision class described above is now structurally impossible: the engine looks up the actual field
  by name instead of searching the entire event's flattened text for the value.
- The only remaining full-text search path is Sigma's field-less `keywords:` list shape (a bare list of
  strings with no field name at all) — full-text search is the *correct* semantics there, not a
  workaround, since there's nothing to look up by name.
- **Regression + smoke-test tool**: `backend/cysiemstack/detection/validate_sigma_rules.py` — loads the
  full corpus and runs a set of hand-built benign events (one per logsource this platform ingests) plus
  known-bad events (do the 3 starter rules and a couple of imported AWS rules still fire correctly) and
  reports PASS/FAIL. All 13 fixtures passed after the fix (0 benign false matches, all known-bad events
  still detected). **This is an offline smoke test only** — it proves the hand-built fixtures don't
  misfire, not that the full ~3,700-rule corpus is silent against everything a real environment
  produces. No live-tenant/production traffic has validated this corpus; watch rule IDs
  101150-101153 (CyCollector) / 101380-101383 (cloud connectors) in the Alert Feed after the first
  stretch of real traffic post-deploy.
- **Corpus grew from 279 → 3,736 rules** (3 starters + this = ~3,739 total): re-ran
  `import_sigma_rules.py` (now preserving upstream subdirectory structure under `--dest`, since
  flattening filenames at this scale caused real collisions) against SigmaHQ's `rules/` (3,129),
  `rules-emerging-threats/` (467), and `rules-threat-hunting/` (140). Deliberately excluded:
  `rules-placeholder/` (would all fail the placeholder filter anyway), `unsupported/` (SigmaHQ
  maintainers already flag these as unreliable), `deprecated/`, `rules-compliance/` (out of scope —
  compliance-framework mapping, not threat detection). See
  `rules/imported/ATTRIBUTION.md` for the full provenance table and license terms (DRL 1.1).
  `identity/` rules (okta/onelogin/cisco `logsource.product`) load but stay dormant — no connector
  supplies that hint yet; this is expected, not a bug, given the "rule coverage ahead of connector
  coverage" decision above.
- **Performance note**: logsource routing measured as a ~3x latency win, not just a correctness fix —
  5.7ms/event when routed to the matching product's rules vs. 17.8ms/event evaluating all ~3,739 rules
  unfiltered (measured locally, single-threaded, non-matching fixture). At CyCollector's default
  500-event ship batch size this keeps Sigma matching well under the 5s ship interval even fully loaded.

## 5. Phase 1 — CyCollector agent — ✅ SHIPPED v1.0.207

Scope was deliberately collection + transport only, dual-running alongside Wazuh with zero
production risk. No cutover happened. Delivered:

| File | What it does |
|---|---|
| `backend/blueprints/collector/routes.py` | `collector_bp` at `/api/collector/*`. `POST /agents/self-enroll` (reuses CyEDR's `edr_deployment_tokens` / `blueprints.edr.policy_engine.validate_deployment_token`), `POST /logs` (Bearer, batched, max 5000 events/request), `POST /heartbeat` (Bearer), `GET /agents` + `GET /agents/<id>` (viewer+, session RBAC). |
| `backend/cysiemstack/collector_bridge.py` | `push_collector_events(agent, events)` wraps each raw event into a synthetic Wazuh envelope and pushes onto the existing `cysiemstack:alerts:raw` Redis list. Rule ID **101100** (see §10), level 3 → maps to `low` severity — deliberately below the HIGH/CRITICAL auto-case-open gate. |
| `agent/cycollector_agent.py` | Standalone Python agent (NOT merged into `cyedr_agent.py`). `JournaldReader` (Linux), `MacOSLogReader` (`log stream --style ndjson`), `WindowsEventLogReader` (`win32evtlog`, lazy import). Batches to `/api/collector/logs` every 5s; heartbeats every 60s. |
| `collector_agents` table | Hardware-UUID dedupe pass, same pattern as `edr_agents`. |

**Explicitly NOT done:** no decode/detection engine (events land as undifferentiated `system`/`low`
alerts), no portal UI, no cutover of any kind.

## 6. Phase 2 — Kafka bus — ⚠️ PRODUCER CODE SHIPPED (v1.0.208), DISABLED BY DEFAULT

**What shipped:**

| File | What it does |
|---|---|
| `backend/core/config.py` | `KAFKA_ENABLED` (default `false`), `KAFKA_BROKERS` (default `127.0.0.1:9092`). |
| `backend/cysiemstack/kafka_bridge.py` | Best-effort `KafkaProducer` wrapper (`kafka-python`). Never raises. Topics: `raw.syslog`, `raw.edr`, `raw.network` (reserved), `raw.audit` (reserved), `raw.splunk`, `raw.qradar`, `raw.sentinelone`, `raw.paloalto` (added in Phase 3 — see `VENDOR_TOPICS` dict). |
| `collector_bridge.py` / `edr_bridge.py` / `connector_bridge.py` | All publish to Kafka additively alongside their existing Redis push. A Kafka failure never affects the Redis-based return value. |
| `backend/requirements.txt` | `kafka-python>=2.0.2`, `redis>=5.0.8` (the latter was a pre-existing gap — `edr_bridge.py` already needed it and it wasn't listed). |

**What did NOT happen:** no Kafka broker exists anywhere. `KAFKA_ENABLED=false` means this is inert
in production today. Provisioning a broker is a **real infrastructure decision requiring explicit
sign-off** — coordinate with g-cyra-devops. Single-broker KRaft mode is the pragmatic starting point
given Cy360's bare-metal, no-Docker, single-node deployment model (`feedback_no_docker` memory).

**Remaining tasks:** provision broker → set `KAFKA_ENABLED=true` + `KAFKA_BROKERS` in
`/opt/cycentra/.env` → retention/partition tuning once Phase 4 workers exist to consume these topics
(they are write-only today, nothing reads them yet, on either the CyCollector/EDR topics or the new
per-vendor connector topics).

## 7. Phase 3 — Multi-vendor SIEM connectors — ⚠️ CODE SHIPPED (v1.0.209-211), UNVERIFIED AGAINST LIVE TENANTS

**Goal:** aggregate Wazuh, Splunk, QRadar, SentinelOne, Palo Alto Cortex XDR/XSIAM, and (v1.0.212+)
Office 365, Azure AD, AWS, and GCP into CyDataLake as pull-based connectors, reusing the exact
synthetic-envelope pattern from Phase 1/2 — zero changes to the correlation engine.

**The four cloud connectors (v1.0.212) matter beyond "one more source":** they're the first
ingestion path in this entire platform that doesn't need Wazuh installed at all for cloud log
coverage. Before this, O365/Azure/AWS/GCP logs were 100% mediated through Wazuh wodles
(`blueprints/system/routes.py`'s O365 config route literally writes into `ossec.conf` and restarts
`wazuh-manager`) — a client answering "no" to the new Wazuh-optional installer prompt (§3) had zero
cloud log ingestion. Now they don't.

**What shipped:**

| File | What it does |
|---|---|
| `backend/cysiemstack/connectors/base.py` | `BaseConnector` ABC — `pull(cursor) -> (events, next_cursor)`, `test_connection()`. Connectors are thin HTTP clients; they never touch Redis/Kafka directly. |
| `backend/cysiemstack/connectors/wazuh_connector.py` | Polls the Wazuh **indexer** (OpenSearch) `wazuh-alerts-*` via `_search`, sorted/paged by `@timestamp`. Returns documents already in native Wazuh envelope shape — no translation needed. **This runs alongside the existing `cysiem_to_redis.py` file-tail, not instead of it** — see the dedup caveat below. |
| `backend/cysiemstack/connectors/splunk_connector.py` | Splunk REST Search API (`/services/search/jobs`), default SPL `search index=notable` (ES notable events), Bearer token auth. Blocking poll-for-completion inside `pull()` (capped at `poll_timeout_sec`, default 60s). |
| `backend/cysiemstack/connectors/qradar_connector.py` | QRadar `/api/siem/offenses`, `SEC` header auth, incremental via `last_persisted_time` (epoch ms). |
| `backend/cysiemstack/connectors/sentinelone_connector.py` | SentinelOne `/web/api/v2.1/threats`, `ApiToken` auth, incremental via `createdAt`, handles S1's own page cursor internally (capped at 10 pages/poll). |
| `backend/cysiemstack/connectors/paloalto_connector.py` | Cortex XDR/XSIAM `/public_api/v1/incidents/get_incidents`, "Advanced" auth scheme (SHA256 of api_key+nonce+timestamp), incremental via `modification_time` (epoch ms). |
| `backend/cysiemstack/connectors/office365_connector.py` (v1.0.212) | Office 365 Management Activity API. OAuth2 client-credentials against Azure AD, subscribes to content types (Audit.AzureActiveDirectory/Exchange/SharePoint/General, DLP.All) then lists+fetches content blobs per 24h window. Bypasses the Wazuh O365 wodle entirely. |
| `backend/cysiemstack/connectors/azure_connector.py` (v1.0.212) | Microsoft Graph API `auditLogs/signIns` + `auditLogs/directoryAudits`, same OAuth2 app-registration model as O365 (can share one Azure AD app with both permission sets). Incremental via `createdDateTime`/`activityDateTime`. |
| `backend/cysiemstack/connectors/aws_connector.py` (v1.0.212) | AWS CloudTrail via `boto3`'s `lookup_events` (not S3 polling — no bucket policy setup needed, covers 90 days out of the box). Lazy-imports `boto3`. |
| `backend/cysiemstack/connectors/gcp_connector.py` (v1.0.212) | GCP Cloud Audit Logs via `google-cloud-logging`'s `list_entries`. Lazy-imports the GCP SDK. Only one of the four cloud connectors with a real documented severity taxonomy (GCP's `LogSeverity` enum) — the other three use operation/event-name heuristics. |
| `backend/cysiemstack/connectors/registry.py` | `CONNECTOR_REGISTRY` vendor-string → class map; `build_connector(vendor, config)`. |
| `backend/cysiemstack/connector_bridge.py` | Normalizes vendor-native events into the synthetic envelope (severity-mapped rule_id per vendor) and pushes to Redis + Kafka. Wazuh is passthrough (already native shape). The four cloud connectors' normalizers (v1.0.212) check `get_engine().match_raw()` first — a real imported Sigma rule match (rule_id 101380-101383) overrides the vendor's own heuristic mapping — before falling back to their operation/event-name heuristics; see §4 for why this only activates when `SIGMA_IMPORTED_RULES_ENABLED=true`. |
| `backend/blueprints/connectors/routes.py` | `connectors_bp` at `/api/connectors/*`. Full CRUD (admin for write, viewer for read), `POST /<id>/test` (analyst+), `POST /<id>/pull` (analyst+, manual trigger — same code path as the scheduler). Secrets (`password`/`api_token`/`sec_token`/`api_key`) masked as `•STORED•` on every GET, same convention as ITAM's `itam_settings()`. New table: `siem_connectors`. |
| `blueprints/scheduler/routes.py` | `register_connector_scheduler()` registers a single dispatcher job (`siem_connector_poll_dispatcher`, every 60s) that pulls any enabled connector whose `poll_interval_sec` has elapsed — not one APScheduler job per connector, so interval edits via `PUT` don't require job add/remove. |
| `portal/src/pages/connectors/index.jsx` (v1.0.210+) | CRUD UI: connector list with status dot/last-pull/events-pulled, add/edit form (vendor-specific fields), Test/Pull Now/Edit/Delete row actions. Registered as "CyDataLake → SIEM Connectors" in `navConfig.jsx`/`AppRouter.jsx`. Not yet run through `npm run build` or exercised in a browser in this session — see the deploy note in the ops runbook. |

**Rule ID allocation added (see §10 for the full table):** `101300-101303` Splunk,
`101310-101313` QRadar, `101320-101323` SentinelOne, `101330-101333` Palo Alto — each block is
critical/high/medium/low, mapped from the vendor's own severity field.

**What did NOT happen — read before telling anyone this is "live":**
- **Zero live-tenant verification.** No Splunk/QRadar/SentinelOne/Cortex/Wazuh-indexer credentials
  were available in this session. Every connector was written against each vendor's publicly
  documented REST API from training knowledge, not tested against a running instance. Specific
  risk areas to verify before trusting this in production:
  - **Palo Alto Cortex "Advanced" auth** (nonce+timestamp+SHA256 hash construction) is the most
    likely to be subtly wrong or version-specific — verify against the target tenant's actual API
    docs before relying on it.
  - **Splunk notable-event field names** (`urgency`, `rule_title`, `search_name`) assume a
    standard Splunk ES deployment; a raw-index-only Splunk deployment will need `search_query`
    reconfigured and `_normalize_splunk()` field names revisited.
  - **QRadar's numeric severity scale** (0-10) bucket thresholds (`>=8` critical, `>=6` high, `>=4`
    medium) are a reasonable default, not a documented QRadar convention — confirm against how the
    target QRadar deployment actually uses its 0-10 scale.
  - **SentinelOne's severity mapping** is the weakest of the four — S1's threat object doesn't have
    a direct 4-tier severity field like the others, so `confidenceLevel` (`malicious`/`suspicious`)
    is being stretched into critical/high/medium. Revisit once real S1 data is available.
- **No Kafka broker** (see §6) — connector events currently only actually land anywhere via the
  Redis push; the Kafka publish is real code but has nowhere to send to.
- **Wazuh dual-path double-ingestion is now mitigated, not eliminated.** Phase 4's
  `cysiemstack/dedup.py` (short-TTL Redis SETNX guard, keyed on vendor+entity+description+minute)
  is wired into `connector_bridge.py` and will collapse most same-alert duplicates if both
  `cysiem_to_redis.py` and `WazuhConnector` run against the same cluster — but it's a narrow,
  conservative key (see §8), not a semantic fix, and was never exercised against real duplicate
  traffic. Safer default is still: only turn on `WazuhConnector` for a cluster where the file-tail
  path is being phased out.
- **Secrets stored in plaintext Postgres** (`siem_connectors.config` JSONB), masked only in API
  responses — same convention as `itam_settings`, but worth a security-review pass given these are
  now credentials for five different external platforms, not just SSH/WinRM lab creds.

**Acceptance criteria for calling Phase 3 done:** each connector's `test_connection()` succeeds
against a real tenant, at least one `pull()` cycle produces correctly-severity-mapped alerts visible
in the Cy360 Alert Feed for each vendor, and the Wazuh dual-path dedup question above is answered.

## 8. Phase 4 — CyDataLake storage + cross-source correlation — ⚠️ CODE SHIPPED (v1.0.210), NOTHING PROVISIONED

**Goal:** stand up the actual hot/cold storage layer and consume the Kafka topics that Phases 1-3
only produce into today.

**What shipped:**

| File | What it does |
|---|---|
| `backend/cysiemstack/dedup.py` | Cross-source duplicate suppression — short-TTL (default 120s) Redis SETNX guard keyed on `sha256(vendor|entity|description|timestamp-rounded-to-minute)`. Wired into `connector_bridge.py` before the Redis/Kafka push. Deliberately conservative: fails open (allows the alert through) on any Redis error, since a false "not a duplicate" is a lesser failure than silently dropping a real alert. |
| `backend/cysiemstack/clickhouse_store.py` | Best-effort ClickHouse client (`clickhouse-connect`), same disabled-by-default/never-block convention as `kafka_bridge.py`. `write_events()` batch-inserts into `<db>.raw_events`. `export_and_purge_older_than()` is the cold-storage step: Parquet-exports rows older than N days via `query_arrow()` + `pyarrow`, then explicitly `ALTER TABLE ... DELETE`s them — a visible, on-purpose archival step, not a silent TTL eviction. |
| `backend/cysiemstack/ingest_worker.py` | **Standalone process** (not part of Flask/gunicorn) — a Kafka consumer across all 8 topics that writes every event into the ClickHouse hot store. Pure fan-out storage; does NOT re-run detection and does NOT re-push to the Redis alert queue — that already happened synchronously in `collector_bridge.py`/`edr_bridge.py`/`connector_bridge.py` at ingest time. Runs a daily cold-storage export loop in a background thread. Idles safely (retries every 60s, never crashes) if `KAFKA_ENABLED`/`CLICKHOUSE_ENABLED` are false or unreachable. |
| `backend/requirements.txt` | Added `clickhouse-connect`, `pyarrow`. |

**What did NOT happen:** no ClickHouse server provisioned, no Kafka broker provisioned (still Phase
2's gap), the ingest worker has never actually run against real data, and `query_arrow()`'s exact
behavior (used by the cold-storage export) hasn't been exercised against a live ClickHouse instance.
See `docs/CYDATALAKE_OPS_RUNBOOK.md` §2-3 for the exact provisioning + systemd deployment steps.

**Acceptance criteria:** ClickHouse provisioned and reachable; ingest worker running as a systemd
service consuming real Kafka traffic; a synthetic duplicate test case demonstrably collapsed by
`dedup.py`; a cold-storage export cycle observed to Parquet-export and purge aged rows correctly.

## 9. Phase 5 — Rebuild Wazuh-Manager-API-dependent fleet features — ✅ AUDIT COMPLETE, NO CODE REWRITTEN (BY DESIGN)

**Full route-by-route audit done — see `docs/SIEM_PROXY_AUDIT.md`.** Every one of `siem_proxy.py`'s
~80 routes was grepped and traced for actual `WAZUH_API_URL`/`_wazuh_auth_token()` usage (not
guessed at) and classified into: zero-Wazuh-dependency (keep forever, not in scope), confirmed
Wazuh-dependent (retire/rebuild candidates with specific recommendations per route), and a small
"needs live-instance verification" group that wasn't confidently traced.

**Why no code was rewritten in this pass, deliberately:** `siem_proxy.py` serves live production
traffic — real agent enroll/remove/isolate, real endpoint policy sync. Rewriting any of it without a
live Wazuh Manager to test against (none was available this session, same constraint as Phase 3's
connectors) risks silently breaking real fleet management, which the migration doc has called the
highest-blast-radius risk in this entire program since the first draft. An audit is safe and
reversible; a blind rewrite of live enroll/remove endpoints is neither — this is the one phase where
"go build it" was scoped down to "produce the safe, valuable analysis and stop there."

Headline findings (full detail + recommended sequencing in `docs/SIEM_PROXY_AUDIT.md`):
- Confirmed zero-Wazuh-dependency: `/health`, `/stats`, all `/incidents/*`, `/fp-patterns/*`,
  `/risk-scores`, all `/ueba/*`, `/alerts*`, `/config`, `/engine/*`, all `/threat-hunting/*`,
  `/posture/internal`, and `/hosts/<id>/tier`+`/enrich`+`/item-statuses` (Postgres-only annotations
  keyed on agent_id, indifferent to which vendor that agent_id came from).
- Confirmed Wazuh-dependent: `/wazuh-launch` + `/internal/auth` (retire candidates),
  `/hosts`+`/hosts/refresh`+`/hosts/<id>` (rebuild as a cross-source view, not 1:1),
  `/hosts/<id>/inventory` + `/hosts/<id>/vulnerabilities` (retire in favor of ITAM),
  `/hosts/<id>/sca` (genuine rebuild needed, no existing overlap), all 8 `/agent-groups/*` routes
  (rebuild-or-retire, needs a product call), `/endpoint-policies/sync` specifically (retire the
  Wazuh-writing mechanics, overlaps with CyEDR's `APPLY_POLICY`; the rest of `/endpoint-policies/*`
  is generic Postgres CRUD and stays).

## 10. Phase 6 — Phased cutover (NOT STARTED — cannot start yet, dependencies unmet)

"Cutover" now means *reducing reliance on any single vendor as the sole source*, not eliminating
Wazuh — Wazuh remains a valid, supported connector going forward. **The full sequenced checklist now
lives in `docs/CYDATALAKE_OPS_RUNBOOK.md` §5** (it's an operational runbook, not architecture, so it
belongs there) — summary:
1. Ingestion first (lowest risk — dual-written since Phase 3/4), once Phases 2-4 have run against
   real Kafka/ClickHouse/vendor traffic for an agreed burn-in period (2+ weeks recommended).
2. Phase 5's audited routes get rewritten one capability at a time, ingestion-adjacent first.
3. Fleet management (agent enroll/remove/isolate) cuts over last, per the sequencing already laid
   out in `docs/SIEM_PROXY_AUDIT.md`.

Do not decommission any vendor's manager/console on a given deployment until every capability that
deployment relies on has an equivalent in Cy360 and has been stable through an agreed burn-in period.
**This phase genuinely cannot start today** — nothing in Phases 2-4 has touched real infrastructure
yet, so there is no "cut over to" target to point at.

## 11. Rule ID / synthetic alert registry (shared resource — check before allocating new IDs)

The correlation engine recognizes non-Wazuh sources purely by rule_id ranges checked in
`normaliser._classify_category()` — collisions are silent. **Before adding any new synthetic
rule_id, grep `CYSIEM-Config/rules/cy_cust_rules.xml` for real Wazuh rule IDs in that range and grep
`normaliser.py` / `edr_bridge.py` / `collector_bridge.py` / `connector_bridge.py` for existing
synthetic ranges.**

| Range | Owner | Notes |
|---|---|---|
| 100100–101042 (sparse, real IDs go up to 101042) | Wazuh (`cy_cust_rules.xml`) | Real rules loaded into Wazuh manager |
| 100210–100211 | CyEDR YARA (bundled/custom) | `blueprints/edr/routes.py` `_ingest_yara_scan_result()` |
| 100300–100399 | CyEDR behavioral detections | `blueprints/edr/confidence_matrix.py` |
| 101100–101109 | CyCollector generic ingestion (Phase 1) | 101100 = unmatched/undetected fallback — 101101-101109 reserved for future per-source-type categorisation |
| **101150–101153** | **Sigma-matched CyCollector events (Phase 0, critical/high/medium/low)** | `cysiemstack/detection/sigma_engine.py` `SIGMA_RULE_IDS` — in use today (3 starter rules) |
| **101200–101299** | **Reserved for future expanded `raw.syslog` detection work** | Not yet in use — the Sigma engine's own IDs live in 101150-101153; this block is for whatever detection logic comes after the 3-rule starting point (e.g. a larger Sigma rule pack) |
| **101300–101303** | **Splunk connector (critical/high/medium/low)** | `cysiemstack/connector_bridge.py` `_RULE_IDS["splunk"]` |
| **101310–101313** | **QRadar connector** | `_RULE_IDS["qradar"]` |
| **101320–101323** | **SentinelOne connector** | `_RULE_IDS["sentinelone"]` |
| **101330–101333** | **Palo Alto Cortex connector** | `_RULE_IDS["paloalto"]` |
| **101340–101343** | **Office 365 connector (v1.0.212)** | `_RULE_IDS["office365"]` |
| **101350–101353** | **Azure AD / Entra ID connector (v1.0.212)** | `_RULE_IDS["azure"]` |
| **101360–101363** | **AWS CloudTrail connector (v1.0.212)** | `_RULE_IDS["aws"]` |
| **101370–101373** | **GCP Cloud Audit Logs connector (v1.0.212)** | `_RULE_IDS["gcp"]` |
| **101380–101383** | **Sigma-matched CLOUD CONNECTOR events (v1.0.212, opt-in only)** | `cysiemstack/detection/sigma_engine.py` `CONNECTOR_SIGMA_RULE_IDS` — distinct from 101150-153 so an operator can tell CyCollector-Sigma from connector-Sigma matches apart |
| 200100–200199 | ASM synthetic findings | `cysiemstack/edr_bridge.py` `_ASM_RULE_IDS` |
| 200200–200299 | ITAM synthetic findings (CVE/IoT/shadow-AI) | `cysiemstack/edr_bridge.py` `_ITAM_RULE_IDS` |

Note Wazuh pulled via `WazuhConnector` needs **no synthetic ID** — it passes through with its own
real rule_id/level already attached, since the indexer document is already in native Wazuh shape.

Severity mapping reminder (`grouper._score_to_severity()`): level 15→critical, 12-14→high,
7-11→medium, 3-6→low. `normaliser.MIN_RULE_LEVEL = 3` — anything below level 3 is silently dropped.

## 12. Risks

- **Sigma false-positive risk from haystack/substring matching at scale** — confirmed, not
  theoretical: testing the imported 279-rule corpus found short/common field values (e.g.
  `event_type_id: 3`, `userIdentity.type: Root`) matching completely unrelated events purely via
  substring collision, and no logsource-based rule routing means every loaded rule evaluates against
  every event regardless of source. This is exactly why the imported corpus defaults to disabled
  (`SIGMA_IMPORTED_RULES_ENABLED=false`) — do not flip it to true in production without either
  curating the rule set down or building real per-field/logsource-aware matching first (§4, §14).
- **CyCollector's raw-log detection is still the one place a from-scratch decoder/rule problem
  exists** — everything else is now aggregation of already-detected data, which is a materially
  smaller and safer engineering problem than the original "replace Wazuh's rule engine" framing.
- **Per-vendor API drift** — every connector in Phase 3 was written from documented API shapes, not
  tested against a live tenant. Field names, auth schemes (especially Cortex's), and severity scales
  can differ by product version/tier. Treat every connector as "needs a pilot customer" before GA.
- **Cross-source duplicate incidents** (§8) — didn't exist as a problem before Phase 3. `dedup.py`
  (Phase 4) mitigates it with a narrow, conservative key but has never seen real duplicate traffic —
  treat it as a first pass, not a solved problem.
- **Credential storage** — five vendors' worth of API keys/tokens now live in `siem_connectors`,
  following the existing (Postgres-plaintext + UI-mask) convention rather than a vault. Worth a
  dedicated security review given the blast radius of a leaked QRadar/Cortex/S1 token.
- **Kafka AND ClickHouse operational weight** on a bare-metal, no-Docker, single-node deployment
  model — two new pieces of SRE surface, not one. Confirm with g-cyra-devops before provisioning
  either (`docs/CYDATALAKE_OPS_RUNBOOK.md` has the concrete steps once approved).
- **`siem_proxy.py` rewrite risk** (Phase 5) — same class of race-condition/migration bug already
  seen in production (`project_v157_fixes` memory). This is exactly why Phase 5 stopped at an audit
  (`docs/SIEM_PROXY_AUDIT.md`) instead of shipping a rewrite.
- **Agent sprawl** if CyCollector isn't eventually merged with the CyEDR agent.
- **Everything in Phases 0/2/3/4 is unverified against real traffic** — this entire program went
  from "not started" to "code-complete" across Phases 0-5 in a compressed session with no live
  infrastructure or vendor credentials available. Treat all of it as a strong first draft that needs
  a real pilot, not as production-hardened code merely because it exists and passes AST checks.

## 13. Reference file map

| Concern | File |
|---|---|
| Correlation engine (reused unchanged across all phases) | `backend/cysiemstack/correlation_engine/{ingestor,normaliser,grouper,correlator,risk_scorer}.py` |
| Proven synthetic-source integration pattern | `backend/cysiemstack/edr_bridge.py` |
| Existing Wazuh file-tail (still running) | `backend/cysiemstack/cysiem_to_redis.py` |
| CyCollector backend (Phase 1) | `backend/blueprints/collector/routes.py`, `backend/cysiemstack/collector_bridge.py` |
| CyCollector agent (Phase 1) | `agent/cycollector_agent.py` |
| Kafka producer wrapper + topic registry (Phase 2) | `backend/cysiemstack/kafka_bridge.py` |
| Kafka config flags | `backend/core/config.py` — `KAFKA_ENABLED`, `KAFKA_BROKERS` |
| Connector framework + all 9 vendor connectors (Phase 3) | `backend/cysiemstack/connectors/` |
| Connector normalization + push (Phase 3) | `backend/cysiemstack/connector_bridge.py` |
| Connector CRUD/scheduler API (Phase 3) | `backend/blueprints/connectors/routes.py` |
| Connector management UI (Phase 3) | `portal/src/pages/connectors/index.jsx` |
| Sigma detection engine + starter rules (Phase 0) | `backend/cysiemstack/detection/sigma_engine.py` |
| Imported SigmaHQ rule corpus (opt-in, 279 rules) + importer tool | `backend/cysiemstack/detection/rules/imported/`, `import_sigma_rules.py` |
| Rules pulled out for containing unfilled placeholders | `backend/cysiemstack/detection/rules_needs_configuration/` |
| Cross-source dedup (Phase 4) | `backend/cysiemstack/dedup.py` |
| ClickHouse hot store (Phase 4) | `backend/cysiemstack/clickhouse_store.py` |
| Standalone ingest worker (Phase 4, separate systemd service) | `backend/cysiemstack/ingest_worker.py` |
| Fleet/host management audit (Phase 5) | `docs/SIEM_PROXY_AUDIT.md` — analysis only, `backend/siem_proxy.py` itself unchanged |
| ITAM overlap candidates (Phase 5 dedup audit) | `backend/blueprints/itam/routes.py` |
| Wazuh custom rule IDs (check before allocating new synthetic IDs) | `CYSIEM-Config/rules/cy_cust_rules.xml` |
| Wazuh-optional installer step | `cycentra-setup.sh` — search `_INSTALL_CYSIEM` |
| All manual infra/credential steps (Phases 2-4, cutover, cloud connector setup) | `docs/CYDATALAKE_OPS_RUNBOOK.md` |
| Release history | `docs/RELEASE_NOTES.md` (v1.0.207 Phase 1, v1.0.208 Phase 2, v1.0.209 Phase 3, v1.0.210 Phases 0/4/5, v1.0.212 Wazuh-optional + cloud connectors + Sigma bulk-import) |

## 14. Open questions for the product owner (do not guess — ask)

- ~~**Sigma field-matching precision**~~ — **RESOLVED v1.0.213.** Product owner decided: keep the
  `SIGMA_IMPORTED_RULES_ENABLED` kill switch (now defaulting to `true`) but stop treating the corpus as
  opt-in, and import the full SigmaHQ corpus (not a curated subset) since source-integration count is
  expected to grow substantially and hand-curation wouldn't scale. Real per-field structured matching
  (`SigmaRule._lookup_field`) and `logsource`-based rule routing (`SigmaRule.matches_logsource`) were
  built to make that safe — see the v1.0.213 update in §4. Remaining open item: no live-tenant traffic
  has validated the corpus yet (only the offline `validate_sigma_rules.py` smoke test) — watch the
  Alert Feed's Sigma rule IDs closely after first real deploy, per §4.
- Kafka footprint: single-broker KRaft acceptable, or a proper cluster? (Ops runbook assumes
  single-broker as the pragmatic starting point.)
- Which vendor should get real credentials first for pilot verification — Wazuh (lowest risk, no
  field-mapping translation needed) is the natural first candidate over Splunk/QRadar/S1/Cortex/the
  four cloud connectors.
- Should `agent/cycollector_agent.py` and `agent/cyedr_agent.py` be merged? (Recommendation: after
  Phase 4 is proven with real traffic, not before — don't destabilize two systems at once.)
- Wazuh dual-path (file-tail + `WazuhConnector`) — run both with `dedup.py` mitigating duplicates,
  or treat `WazuhConnector` as the eventual replacement for the file-tail on a per-cluster basis?
- Now that Wazuh is optional at install time (v1.0.212), should the default answer to that prompt
  ever flip to "no"? Not recommended until the Sigma field-matching gap above and the cloud
  connectors have real pilot verification — see the coverage gap called out in §3's new subsection.
- `/agent-groups/*` and `/wazuh-launch` (Phase 5 audit, `docs/SIEM_PROXY_AUDIT.md`) — product call
  needed on whether these are worth rebuilding at all versus retiring outright.
- ClickHouse vs. OpenSearch for the hot store — this session implemented against ClickHouse
  (lighter-weight, better single-node fit) but this wasn't a validated decision, just a
  recommendation; revisit if OpenSearch's fuller-text-search features turn out to matter more.
