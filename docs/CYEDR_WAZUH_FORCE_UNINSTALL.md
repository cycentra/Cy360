# CyEDR + Wazuh (CySIEM) — Force Uninstall Guide

**Audience:** Operators / Support engineers removing agents from an endpoint (Ubuntu or macOS)
**Scope:** Complete, forcible removal of the CyEDR agent and/or the Wazuh (CySIEM) agent — including stuck, partial, or corrupted installs where the normal uninstaller doesn't fully clean up.
**Companion doc:** [CYEDR_TECHNICAL_REFERENCE.md](CYEDR_TECHNICAL_REFERENCE.md) §3 — normal installation flow (`cyedr-install.sh` / `--with-cysiem`)

---

## Before you start

- Run every command below as **root** (`sudo`). Both agents install services, files, and (on Linux) an OS user outside any single user's home directory.
- "Force" here means: stop by every mechanism available, then delete by path rather than relying solely on a package manager's uninstall hook — useful when a service is wedged, the package DB is out of sync with what's on disk, or the agent was deployed as a standalone binary (no `.deb`/`.pkg` record at all).
- These steps remove the agent **locally only**. See [§5 Platform-side cleanup](#5-platform-side-cleanup) — the endpoint's record on the CyCentra 360 platform is not automatically deleted by any of this.
- If you only want to remove one of the two agents (they are independent — CyEDR does not depend on Wazuh being present), skip straight to that section.

---

## 1. Ubuntu — Force Uninstall CyEDR Agent

CyEDR on Linux consists of: a systemd service (`cyedr-agent`) + watchdog timer, an auditd rules file, an audisp plugin, a dedicated `cyedr` system user, and everything under `/opt/cycentra/edr`.

```bash
#!/usr/bin/env bash
# Force-remove CyEDR agent — Ubuntu / any systemd Linux
set -x

# 1. Stop and disable every CyEDR service, regardless of current state
systemctl stop cyedr-agent cyedr-watchdog.timer cyedr-watchdog.service 2>/dev/null
systemctl disable cyedr-agent cyedr-watchdog.timer cyedr-watchdog.service 2>/dev/null

# 2. Belt-and-braces: kill any surviving process by name (handles a wedged
#    unit, or a binary that was ever run manually / outside systemd)
pkill -9 -f 'cyedr-agent' 2>/dev/null
pkill -9 -f 'cyedr_agent.py' 2>/dev/null

# 3. Remove systemd unit files and reload
rm -f /etc/systemd/system/cyedr-agent.service \
      /etc/systemd/system/cyedr-watchdog.service \
      /etc/systemd/system/cyedr-watchdog.timer
systemctl daemon-reload
systemctl reset-failed 2>/dev/null

# 4. Remove CyEDR's auditd rules + audisp plugin, then reload auditd
#    (leaves Wazuh's own auditd rules untouched — different key prefix)
rm -f /etc/audit/rules.d/60-cyedr.rules
rm -f /etc/audisp/plugins.d/cyedr.conf
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true

# 5. Remove the leftover audit socket, if still present
rm -f /var/run/cyedr_audit.sock

# 6. Remove the agent's entire home directory — config, YARA rules, IOC
#    cache, quarantine, logs. This is everything the installer created.
rm -rf /opt/cycentra/edr

# 7. Remove the dedicated system user (created by the installer; no login,
#    no home outside /opt/cycentra/edr)
userdel cyedr 2>/dev/null || true

echo "CyEDR agent force-removed."
```

**Verify:**
```bash
systemctl status cyedr-agent 2>&1 | head -1     # → "could not be found" / "Unit ... not found"
pgrep -fa cyedr                                  # → no output
ls /opt/cycentra/edr 2>&1                        # → "No such file or directory"
id cyedr 2>&1                                    # → "no such user"
auditctl -l | grep cy360_edr                     # → no output
```

---

## 2. Ubuntu — Force Uninstall Wazuh (CySIEM) Agent

The CySIEM agent installed via `--with-cysiem` is a stock Wazuh agent (package name `wazuh-agent`, service `wazuh-agent`, home `/var/ossec`). Try the package-manager path first; fall back to the manual block if the package is missing, broken, or `apt` reports it as not-installed while files still exist on disk.

```bash
#!/usr/bin/env bash
# Force-remove Wazuh (CySIEM) agent — Ubuntu / Debian-based
set -x

# 1. Stop by every mechanism, then kill any survivor
systemctl stop wazuh-agent 2>/dev/null
service wazuh-agent stop 2>/dev/null
/var/ossec/bin/wazuh-control stop 2>/dev/null
pkill -9 -f 'wazuh-agentd|wazuh-execd|wazuh-logcollector|wazuh-syscheckd|wazuh-modulesd' 2>/dev/null

# 2. Purge via the package manager (removes config + data with --purge)
apt-get remove --purge -y wazuh-agent 2>/dev/null || true
dpkg --purge wazuh-agent 2>/dev/null || true

# 3. Force-delete anything the package manager missed (common on a
#    corrupted/partial install, or one that was untarred by hand)
systemctl disable wazuh-agent 2>/dev/null
rm -f /etc/systemd/system/wazuh-agent.service \
      /lib/systemd/system/wazuh-agent.service \
      /etc/init.d/wazuh-agent
systemctl daemon-reload
rm -rf /var/ossec
rm -f /etc/apt/sources.list.d/wazuh.list
rm -f /etc/apt/keyrings/wazuh.gpg /usr/share/keyrings/wazuh.gpg

echo "Wazuh (CySIEM) agent force-removed."
```

**Verify:**
```bash
dpkg -l | grep -i wazuh          # → no output
systemctl status wazuh-agent 2>&1 | head -1   # → "could not be found"
pgrep -fa wazuh                  # → no output
ls /var/ossec 2>&1               # → "No such file or directory"
```

---

## 3. macOS — Force Uninstall CyEDR Agent

On macOS, CyEDR runs as a LaunchDaemon (`com.cycentra.edr`), not a systemd service, and the installer does **not** create a dedicated OS user (that step in `cyedr-install.sh` is Linux-only) or any auditd rules (macOS has no auditd). Everything else is the same `/opt/cycentra/edr` tree.

```bash
#!/usr/bin/env bash
# Force-remove CyEDR agent — macOS
set -x

PLIST="/Library/LaunchDaemons/com.cycentra.edr.plist"

# 1. Unload via the modern API, then the legacy one, then kill by hand.
#    Try both — an already-unloaded daemon makes bootout/unload no-ops,
#    that's fine, this block is deliberately over-inclusive.
launchctl bootout system "$PLIST" 2>/dev/null
launchctl unload -w "$PLIST" 2>/dev/null
pkill -9 -f 'cyedr-agent' 2>/dev/null
pkill -9 -f 'cyedr_agent.py' 2>/dev/null

# 2. Remove the LaunchDaemon definition
rm -f "$PLIST"

# 3. Remove the agent's entire home directory
rm -rf /opt/cycentra/edr

echo "CyEDR agent force-removed (macOS)."
```

**Verify:**
```bash
launchctl print system/com.cycentra.edr 2>&1 | head -1   # → "Could not find service"
pgrep -fla cyedr                                          # → no output
ls /opt/cycentra/edr 2>&1                                 # → "No such file or directory"
```

---

## 4. macOS — Force Uninstall Wazuh (CySIEM) Agent

The official Wazuh macOS agent ships its own uninstaller. Try that first; the manual fallback below handles a version where the uninstaller itself is missing or broken, which is the common reason someone reaches for a "force" procedure in the first place.

```bash
#!/usr/bin/env bash
# Force-remove Wazuh (CySIEM) agent — macOS
set -x

# 1. Prefer the vendor-provided uninstaller if it's still present
if [[ -x /Library/Ossec/uninstall.sh ]]; then
    /Library/Ossec/uninstall.sh 2>/dev/null || true
fi

# 2. Stop by every mechanism, then kill any survivor (covers the case
#    where the uninstaller above didn't fully stop the daemon)
launchctl bootout system /Library/LaunchDaemons/com.wazuh.agent.plist 2>/dev/null
launchctl unload -w /Library/LaunchDaemons/com.wazuh.agent.plist 2>/dev/null
/Library/Ossec/bin/wazuh-control stop 2>/dev/null
pkill -9 -f 'wazuh-agentd|wazuh-execd|wazuh-logcollector|wazuh-syscheckd|wazuh-modulesd|ossec-' 2>/dev/null

# 3. Remove the LaunchDaemon definition and the install tree, regardless
#    of whether step 1's uninstaller ran cleanly
rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
rm -rf /Library/Ossec

# 4. Forget the pkg receipt so a future reinstall isn't blocked by macOS
#    thinking the package is already present. Query first — the receipt
#    identifier has changed across Wazuh releases, don't hardcode one.
for _pkgid in $(pkgutil --pkgs | grep -i wazuh); do
    pkgutil --forget "$_pkgid" 2>/dev/null || true
done

echo "Wazuh (CySIEM) agent force-removed (macOS)."
```

**Verify:**
```bash
launchctl print system/com.wazuh.agent 2>&1 | head -1   # → "Could not find service"
pgrep -fla wazuh                                         # → no output
ls /Library/Ossec 2>&1                                   # → "No such file or directory"
pkgutil --pkgs | grep -i wazuh                           # → no output
```

---

## 5. Platform-side cleanup

Removing the local agent does **not** delete its record on the CyCentra 360 platform:

- **Wazuh / CySIEM host:** `DELETE /api/siem/hosts/<agent_id>` (admin only, `siem_proxy.py`) removes the agent from the Wazuh manager via its API and purges the `host_posture_cache` row. This is also exposed in the UI (Host Intelligence → Hosts tab → ✕ on a disconnected agent).
- **CyEDR fleet entry:** there is currently **no deregistration endpoint** for `edr_agents` — no `DELETE /api/edr/agents/<id>` route exists in `blueprints/edr/routes.py` today. After a force uninstall, the row simply stops receiving heartbeats and will age out of "active" status on its own (fleet UI shows it as disconnected based on `last_seen`), but it is not deleted from the database. If you need it gone from the fleet list/DB immediately, that requires a manual `DELETE FROM edr_agents WHERE agent_id = '<id>'` against the `correlation` database — there is no supported API for it yet.

---

## 6. Reinstalling afterward

Once both force-uninstalls are verified clean, a fresh install is the normal one-liner:

```bash
curl -fsSL https://<platform>/api/edr/installer/unix | bash -s -- \
    --token <DEPLOY_TOKEN> --platform https://<platform> --with-cysiem
```

Omit `--with-cysiem` to install CyEDR only.
