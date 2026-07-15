#!/usr/bin/env python3
"""
cysiemstack/detection/validate_sigma_rules.py
================================================
Offline smoke test for the Sigma engine (sigma_engine.py). Runs a small set
of hand-built BENIGN events (one or more per logsource this platform
actually ingests — linux/macos/windows via CyCollector, aws/azure/gcp/
office365 via the cloud connectors) through the full imported corpus and
flags any that match a rule — a benign event matching something is either
a genuine false positive or a fixture that isn't as benign as intended and
needs a second look either way. It also runs a handful of KNOWN-BAD events
through the same path as a regression check that real detections still
fire (a rewrite that silences every false positive by also silencing every
true positive would pass a false-positive-only check and still be wrong).

This is NOT a substitute for shadow-mode validation against real
production traffic — it only proves the fixtures below don't misfire, not
that the full 3700+-rule corpus is silent against everything your actual
environment produces. Deploy with SIGMA_IMPORTED_RULES_ENABLED left at its
default (true) but treat this as the first pre-deploy gate, and watch the
Alert Feed's Sigma-sourced rule IDs (101150-101153, 101380-101383) for the
first stretch of real traffic after every corpus refresh.

Usage:
    cd backend && python3 -m cysiemstack.detection.validate_sigma_rules
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))  # backend/ on path
from cysiemstack.detection.sigma_engine import SigmaEngine  # noqa: E402


def _collector_event(source_type: str, message: str, program: str = "", raw: dict | None = None) -> dict:
    return {"source_type": source_type, "message": message, "program": program, "raw": raw or {}, "metadata": {}}


_SOURCE_TYPE_PRODUCT = {"journald": "linux", "syslog": "linux", "oslog": "macos", "windows_eventlog": "windows"}

# ── Fixtures: (label, kind, payload, logsource_hint, expect_match) ──────────
# kind is "event" (-> engine.match) or "raw" (-> engine.match_raw)
FIXTURES = [
    # -- Benign, should NOT match anything --
    ("linux: normal systemd session start", "event",
     _collector_event("journald", "systemd[1]: Started Session 42 of user deploy.", "systemd"),
     {"product": "linux"}, False),
    ("linux: successful ssh login (not a failure)", "event",
     _collector_event("journald", "Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2", "sshd"),
     {"product": "linux"}, False),
    ("macos: launchd routine service exit", "event",
     _collector_event("oslog", "Service exited normally", "launchd"),
     {"product": "macos"}, False),
    ("windows: routine service state change", "event",
     _collector_event("windows_eventlog", "The Windows Update service entered the running state.",
                       "Service Control Manager", raw={"EventID": 7036, "Channel": "System"}),
     {"product": "windows"}, False),
    ("aws: benign read-only DescribeInstances call", "raw",
     {"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com",
      "userIdentity": {"type": "IAMUser", "userName": "alice"}, "errorCode": None},
     {"product": "aws"}, False),
    ("aws: successful console login WITH mfa", "raw",
     {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
      "userIdentity": {"type": "IAMUser", "userName": "alice"},
      "responseElements": {"ConsoleLogin": "Success"},
      "additionalEventData": {"MFAUsed": "Yes"}, "errorCode": None},
     {"product": "aws"}, False),
    ("azure: benign signin, no risk", "raw",
     {"_ts_field": "createdDateTime", "userPrincipalName": "alice@example.com",
      "riskLevelDuringSignIn": "none", "status": {"errorCode": 0}},
     {"product": "azure"}, False),
    ("gcp: benign INFO audit entry", "raw",
     {"severity": "INFO", "resource": "projects/example/instances/vm-1", "log_name": "cloudaudit.googleapis.com"},
     {"product": "gcp"}, False),
    ("office365: benign file access, succeeded", "raw",
     {"Operation": "FileAccessed", "UserId": "alice@example.com", "ResultStatus": "Succeeded"},
     {"product": "office365"}, False),

    # -- Known-bad, SHOULD match (regression check on real detections) --
    ("linux: ssh failed password (starter rule cy-sigma-0001)", "event",
     _collector_event("journald", "Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2", "sshd"),
     {"product": "linux"}, True),
    ("linux: sudo NOPASSWD abuse (starter rule cy-sigma-0002)", "event",
     _collector_event("journald", "sudo: deploy : NOPASSWD: TTY=pts/0 ; COMMAND=/bin/bash", "sudo"),
     {"product": "linux"}, True),
    ("aws: S3 bucket deleted successfully (imported rule)", "raw",
     {"eventName": "DeleteBucket", "eventSource": "s3.amazonaws.com", "errorCode": "Success"},
     {"product": "aws"}, True),
    ("aws: console login failed authentication (imported rule)", "raw",
     {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
      "errorMessage": "Failed authentication"},
     {"product": "aws"}, True),
]


def main() -> int:
    engine = SigmaEngine(include_imported=True)
    print(f"Loaded {len(engine.rules)} Sigma rule(s)\n")

    failures = 0
    for label, kind, payload, hint, expect_match in FIXTURES:
        if kind == "event":
            matched = engine.match(payload, logsource_hint=hint)
        else:
            matched = engine.match_raw(payload, logsource_hint=hint)

        got_match = matched is not None
        ok = got_match == expect_match
        status = "PASS" if ok else "FAIL"
        detail = f"matched: {matched.title!r} (level={matched.level})" if matched else "no match"
        print(f"[{status}] {label}\n         expected {'a match' if expect_match else 'no match'} -> {detail}")
        if not ok:
            failures += 1

    print(f"\n{len(FIXTURES) - failures}/{len(FIXTURES)} fixtures passed.")
    if failures:
        print("Investigate FAIL lines above before deploying — a benign fixture that matched is a live "
              "false-positive candidate; a known-bad fixture that didn't match is a detection regression.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
