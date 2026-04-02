#!/usr/bin/env python3
"""
Wazuh alerts.json → Redis bridge.

Replaces Filebeat as the ingest mechanism because Filebeat 7.x
(Wazuh-distributed) crashes with a seccomp pthread_create SIGABRT on
Linux kernel 6.x.  This script performs the same job: it tails
/var/ossec/logs/alerts/alerts.json and pushes each NDJSON alert line
as an LPUSH into the Redis list consumed by the CySIEMStack ingestor.

Deployed to: /opt/cycentra/wazuh_to_redis.py
Managed by:  systemd unit  wazuh-to-redis.service
Logs to:     /opt/cycentra/engine.log  (shared with cysiemstack-engine)
"""
import json
import logging
import os
import time
from pathlib import Path

import redis

# ── Configuration ─────────────────────────────────────────────────────────────
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
REDIS_HOST  = "127.0.0.1"
REDIS_PORT  = 6379
REDIS_KEY   = "cysiemstack:alerts:raw"
MAX_LIST    = 200_000   # cap Redis list to avoid unbounded memory growth
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("wazuh_to_redis")


def tail_forever() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    r.ping()

    path = Path(ALERTS_FILE)
    log.info("watching %s  →  redis:%d/%s", ALERTS_FILE, REDIS_PORT, REDIS_KEY)

    # Open in raw unbuffered binary mode so OS-level appends are immediately
    # visible — Python text-mode buffering can silently stall on tailed files.
    with open(path, "rb", buffering=0) as fb:
        fb.seek(0, 2)                         # start at EOF — no history replay
        inode  = os.stat(path).st_ino
        buf    = b""
        pushed = 0

        while True:
            chunk = fb.read(65536)
            if chunk:
                buf += chunk
                # flush every complete newline-terminated line
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)      # validate before pushing
                        pipe = r.pipeline()
                        pipe.lpush(REDIS_KEY, line)
                        pipe.ltrim(REDIS_KEY, 0, MAX_LIST - 1)
                        pipe.execute()
                        pushed += 1
                        if pushed % 100 == 0:
                            log.info("pushed %d alerts total", pushed)
                    except json.JSONDecodeError as exc:
                        log.warning("invalid JSON — skipped: %s", exc)
                    except redis.RedisError as exc:
                        log.error("redis error: %s", exc)
                        raise  # let outer loop reconnect
            else:
                # detect Wazuh daily log rotation
                try:
                    if os.stat(path).st_ino != inode:
                        log.info("log rotation detected — reopening %s", path)
                        buf = b""
                        fb.close()
                        fb = open(path, "rb", buffering=0)
                        inode = os.stat(path).st_ino
                except FileNotFoundError:
                    pass
                time.sleep(0.05)


if __name__ == "__main__":
    while True:
        try:
            tail_forever()
        except Exception as exc:
            log.error("fatal: %s — retrying in 5 s", exc)
            time.sleep(5)
