#!/usr/bin/env bash
# =============================================================================
# patch_incident_grouping.sh
# Fixes: all auth alerts merging into one infinite incident
# Touches: config.py, grouper.py, .env.example, cycentra-setup.sh
# Usage:
#   On the server:   sudo bash patch_incident_grouping.sh
#   In the repo:     bash patch_incident_grouping.sh --repo-only
#   Preview:         bash patch_incident_grouping.sh --dry-run
# =============================================================================
set -euo pipefail

DRY_RUN=false
REPO_ONLY=false
for arg in "$@"; do
  [[ "$arg" == "--dry-run"   ]] && DRY_RUN=true
  [[ "$arg" == "--repo-only" ]] && REPO_ONLY=true
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
info() { echo -e "${CYAN}  → $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
die()  { echo -e "${RED}  ✗ $*${NC}"; exit 1; }

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Walk up until we find cycentra-setup.sh (repo root marker)
REPO_ROOT="$SCRIPT_DIR"
for _ in 1 2 3 4 5; do
  [[ -f "$REPO_ROOT/cycentra-setup.sh" ]] && break
  REPO_ROOT="$(dirname "$REPO_ROOT")"
done
[[ -f "$REPO_ROOT/cycentra-setup.sh" ]] || die "Cannot locate repo root from $SCRIPT_DIR — run from inside the cycentra360 repo."

ENGINE_DIR="$REPO_ROOT/backend/cysiemstack/correlation_engine"
ENV_EXAMPLE="$REPO_ROOT/backend/cysiemstack/.env.example"
SETUP_SH="$REPO_ROOT/cycentra-setup.sh"
SERVER_ENGINE="/opt/cycentra/cysiemstack/correlation_engine"
SERVER_ENV="/opt/cycentra/cysiemstack.env"

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  cycentra360 — Incident Grouping Window Patch            ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo "  Repo root  : $REPO_ROOT"
echo "  Engine dir : $ENGINE_DIR"
echo "  Dry run    : $DRY_RUN"
echo "  Repo only  : $REPO_ONLY"
echo ""

# ── Helper: in-place sed that works on both GNU and BSD/macOS ─────────────────
_sed() {
  # $1 = script, $2 = file
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "$1" "$2"
  else
    sed -i '' "$1" "$2"
  fi
}

backup_and_patch() {
  local file="$1" old="$2" new="$3" label="$4"
  if ! grep -qF "$old" "$file" 2>/dev/null; then
    warn "SKIP ($label): marker not found in $file — already patched?"
    return 0
  fi
  if $DRY_RUN; then
    info "DRY-RUN ($label): would patch $file"
    return 0
  fi
  local bak="${file}.bak_$(date +%Y%m%d_%H%M%S)"
  cp "$file" "$bak"
  # Use python3 for reliable multi-line replacement (no awk/perl dependency)
  python3 - "$file" "$old" "$new" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if old not in text:
    sys.exit(1)
open(path, 'w').write(text.replace(old, new, 1))
PYEOF
  ok "$label → $file (backup: $bak)"
}

# =============================================================================
# PATCH 1 — config.py: add incident_max_age_minutes
# =============================================================================
echo -e "${YELLOW}── [1/4] config.py ─────────────────────────────────────────${NC}"

CONFIG_OLD='    # Correlation engine tuning
    correlation_window_minutes: int = 15'

CONFIG_NEW='    # Correlation engine tuning
    # CORRELATION_WINDOW_MINUTES — idle gap: no activity for N min → next alert
    #   opens a new incident. Effective for spaced attacks.
    # INCIDENT_MAX_AGE_MINUTES   — hard ceiling: an incident stops absorbing
    #   alerts unconditionally after this age, regardless of activity.
    #   This guard is what prevents continuous brute-force from growing one
    #   incident forever.  Set both values in /opt/cycentra/cysiemstack.env.
    correlation_window_minutes: int = 15
    incident_max_age_minutes:   int = 30'

backup_and_patch "$ENGINE_DIR/config.py" "$CONFIG_OLD" "$CONFIG_NEW" "add incident_max_age_minutes"

# =============================================================================
# PATCH 2 — grouper.py: fix find_matching_incident()
# =============================================================================
echo -e "${YELLOW}── [2/4] grouper.py ────────────────────────────────────────${NC}"

GROUPER_OLD='async def find_matching_incident(
    db: AsyncSession,
    alert: dict,
) -> Optional[Incident]:
    """
    Find an open incident that this alert belongs to.
    Matching criteria (all must hold):
      - status = '"'"'open'"'"' or '"'"'investigating'"'"'
      - same agent_id in affected_agents
      - last_seen within correlation window
    """
    window = timedelta(minutes=settings.correlation_window_minutes)
    cutoff = alert['"'"'timestamp'"'"'] - window

    result = await db.execute(
        select(Incident).where(
            Incident.status.in_(['"'"'open'"'"', '"'"'investigating'"'"']),
            Incident.last_seen >= cutoff,
        ).order_by(Incident.last_seen.desc()).limit(20)
    )
    candidates = result.scalars().all()

    for inc in candidates:
        # Same agent check
        if alert.get('"'"'agent_id'"'"') in (inc.affected_agents or []):
            return inc
        # Same src_ip — different agents, same attacker
        if alert.get('"'"'src_ip'"'"') and alert['"'"'src_ip'"'"'] in (inc.src_ips or []):
            return inc

    return None'

GROUPER_NEW='async def find_matching_incident(
    db: AsyncSession,
    alert: dict,
) -> Optional[Incident]:
    """
    Find an open incident that this alert belongs to.

    Two independent guards must BOTH pass:

    1. Idle-gap  (last_seen >= activity_cutoff):
       The incident had activity within CORRELATION_WINDOW_MINUTES.
       Prevents linking alerts from separate sessions with a quiet gap.

    2. Hard ceiling (first_seen >= age_cutoff):
       The incident was opened within INCIDENT_MAX_AGE_MINUTES.
       Without this guard a continuous stream (e.g. brute-force) advances
       last_seen on every merge, so the incident grows without bound.

    Tune both via /opt/cycentra/cysiemstack.env.
    """
    window  = timedelta(minutes=settings.correlation_window_minutes)
    max_age = timedelta(minutes=settings.incident_max_age_minutes)
    now     = alert['"'"'timestamp'"'"']

    activity_cutoff = now - window   # idle-gap guard
    age_cutoff      = now - max_age  # hard-ceiling guard

    result = await db.execute(
        select(Incident).where(
            Incident.status.in_(['"'"'open'"'"', '"'"'investigating'"'"']),
            Incident.last_seen  >= activity_cutoff,   # guard 1
            Incident.first_seen >= age_cutoff,        # guard 2 — THE FIX
        ).order_by(Incident.last_seen.desc()).limit(20)
    )
    candidates = result.scalars().all()

    for inc in candidates:
        # Same agent check
        if alert.get('"'"'agent_id'"'"') in (inc.affected_agents or []):
            return inc
        # Same src_ip — different agents, same attacker
        if alert.get('"'"'src_ip'"'"') and alert['"'"'src_ip'"'"'] in (inc.src_ips or []):
            return inc

    return None'

backup_and_patch "$ENGINE_DIR/grouper.py" "$GROUPER_OLD" "$GROUPER_NEW" "first_seen hard-ceiling guard"

# =============================================================================
# PATCH 3 — .env.example: add INCIDENT_MAX_AGE_MINUTES
# =============================================================================
echo -e "${YELLOW}── [3/4] .env.example ──────────────────────────────────────${NC}"

ENVEX_OLD='CORRELATION_WINDOW_MINUTES=15'
ENVEX_NEW='# CORRELATION_WINDOW_MINUTES — idle gap before a new alert opens a fresh incident
# INCIDENT_MAX_AGE_MINUTES   — hard ceiling; incident stops absorbing after this age
CORRELATION_WINDOW_MINUTES=15
INCIDENT_MAX_AGE_MINUTES=30'

backup_and_patch "$ENV_EXAMPLE" "$ENVEX_OLD" "$ENVEX_NEW" "add INCIDENT_MAX_AGE_MINUTES to .env.example"

# =============================================================================
# PATCH 4 — cycentra-setup.sh: add INCIDENT_MAX_AGE_MINUTES to heredoc
# =============================================================================
echo -e "${YELLOW}── [4/4] cycentra-setup.sh ─────────────────────────────────${NC}"

SETUP_OLD='CORRELATION_WINDOW_MINUTES=15
UEBA_BASELINE_DAYS=30'
SETUP_NEW='CORRELATION_WINDOW_MINUTES=15
INCIDENT_MAX_AGE_MINUTES=30
UEBA_BASELINE_DAYS=30'

backup_and_patch "$SETUP_SH" "$SETUP_OLD" "$SETUP_NEW" "add INCIDENT_MAX_AGE_MINUTES to setup.sh heredoc"

# =============================================================================
# SERVER — sync live files and restart (skipped with --repo-only)
# =============================================================================
if ! $REPO_ONLY && [[ -d "$SERVER_ENGINE" ]]; then
  echo ""
  echo -e "${YELLOW}── [Server] Sync live files ─────────────────────────────────${NC}"

  if $DRY_RUN; then
    info "DRY-RUN: would copy patched files to $SERVER_ENGINE"
    info "DRY-RUN: would add INCIDENT_MAX_AGE_MINUTES to $SERVER_ENV"
    info "DRY-RUN: would restart cysiemstack-engine"
  else
    cp "$ENGINE_DIR/config.py" "$SERVER_ENGINE/config.py"
    ok "Synced config.py → $SERVER_ENGINE/"
    cp "$ENGINE_DIR/grouper.py" "$SERVER_ENGINE/grouper.py"
    ok "Synced grouper.py → $SERVER_ENGINE/"

    # Add env var to live env file if missing
    if ! grep -q "INCIDENT_MAX_AGE_MINUTES" "$SERVER_ENV" 2>/dev/null; then
      cp "$SERVER_ENV" "${SERVER_ENV}.bak_$(date +%Y%m%d_%H%M%S)"
      echo "INCIDENT_MAX_AGE_MINUTES=30" >> "$SERVER_ENV"
      ok "Added INCIDENT_MAX_AGE_MINUTES=30 to $SERVER_ENV"
    else
      warn "INCIDENT_MAX_AGE_MINUTES already in $SERVER_ENV — not overwritten"
    fi

    systemctl restart cysiemstack-engine
    sleep 2
    if systemctl is-active --quiet cysiemstack-engine; then
      ok "cysiemstack-engine restarted successfully"
    else
      die "cysiemstack-engine failed to restart — check: journalctl -u cysiemstack-engine -n 50"
    fi
  fi
elif ! $REPO_ONLY && [[ ! -d "$SERVER_ENGINE" ]]; then
  warn "Server path $SERVER_ENGINE not found — skipping server sync (run on server to apply live)."
fi

# =============================================================================
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Patch complete                                           ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Files changed:"
echo "    backend/cysiemstack/correlation_engine/config.py"
echo "    backend/cysiemstack/correlation_engine/grouper.py"
echo "    backend/cysiemstack/.env.example"
echo "    cycentra-setup.sh"
echo ""
echo "  To tune (edit /opt/cycentra/cysiemstack.env then restart engine):"
echo "    CORRELATION_WINDOW_MINUTES=15   # idle gap before new incident"
echo "    INCIDENT_MAX_AGE_MINUTES=30     # hard ceiling (10–60 recommended)"
echo ""
if [[ -d "$SERVER_ENGINE" ]] && ! $REPO_ONLY && ! $DRY_RUN; then
  echo "  Monitor:"
  echo "    sudo journalctl -u cysiemstack-engine -f | grep -E 'incident_created|incident_merged'"
fi
echo ""