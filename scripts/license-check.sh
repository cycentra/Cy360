#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CyCentra 360 — License Check
# Called by setup.sh and as ExecStartPre in systemd service units.
#
# Exit codes:
#   0  — valid full license (proceed)
#   1  — valid demo license (proceed with demo restrictions)
#   2  — license expired (services must stop)
#   3  — invalid/tampered license (abort)
#   4  — no license (demo auto-mode, first stamp if needed)
#
# Sets:
#   CYCENTRA_LICENSE_TYPE   = full | demo | none
#   CYCENTRA_DAYS_REMAINING = N
#   CYCENTRA_DEMO_MODE      = 1 | 0
# ─────────────────────────────────────────────────────────────────────────────

VALIDATOR="/opt/cycentra/license_validator.py"
LICENSE_FILE="/opt/cycentra/cycentra.lic"

# ── Colours (only when running interactively) ─────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; NC=''; BOLD=''
fi

# ── Run validator ─────────────────────────────────────────────────────────────
if [[ ! -f "$VALIDATOR" ]]; then
    echo -e "${RED}[LICENSE] Validator not found at ${VALIDATOR}${NC}" >&2
    exit 3
fi

_JSON=$(python3 "$VALIDATOR" --license "$LICENSE_FILE" 2>/dev/null)
_CODE=$?

_MSG=$(echo "$_JSON"      | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null)
_TYPE=$(echo "$_JSON"     | python3 -c "import sys,json; print(json.load(sys.stdin).get('type','none'))" 2>/dev/null)
_DAYS=$(echo "$_JSON"     | python3 -c "import sys,json; print(json.load(sys.stdin).get('days_remaining',0))" 2>/dev/null)
_CUSTOMER=$(echo "$_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('customer',''))" 2>/dev/null)

export CYCENTRA_LICENSE_TYPE="${_TYPE:-none}"
export CYCENTRA_DAYS_REMAINING="${_DAYS:-0}"
export CYCENTRA_DEMO_MODE=0
[[ "$_TYPE" == "demo" ]] && export CYCENTRA_DEMO_MODE=1

case $_CODE in
    0)
        echo -e "${GREEN}[LICENSE] ✓ Full license valid — ${_CUSTOMER} — ${_DAYS} day(s) remaining${NC}"
        ;;
    1)
        echo -e "${YELLOW}[LICENSE] ⚠ Demo mode — ${_DAYS} day(s) remaining${NC}"
        echo -e "${YELLOW}[LICENSE]   Features limited to demo set (CySIEM only)${NC}"
        ;;
    2)
        echo -e "${RED}[LICENSE] ✗ License expired — ${_MSG}${NC}" >&2
        echo -e "${RED}[LICENSE]   All CyCentra services will be stopped.${NC}" >&2
        echo -e "${RED}[LICENSE]   Purchase or renew at https://cycentra.com${NC}" >&2
        exit 2
        ;;
    3)
        echo -e "${RED}[LICENSE] ✗ Invalid license — ${_MSG}${NC}" >&2
        echo -e "${RED}[LICENSE]   Installation aborted.${NC}" >&2
        exit 3
        ;;
    4|*)
        echo -e "${YELLOW}[LICENSE] No license file found — starting 15-day demo${NC}"
        echo -e "${YELLOW}[LICENSE] Place cycentra.lic in /opt/cycentra/ to activate full platform${NC}"
        export CYCENTRA_DEMO_MODE=1
        export CYCENTRA_LICENSE_TYPE="demo"
        ;;
esac

exit $_CODE
