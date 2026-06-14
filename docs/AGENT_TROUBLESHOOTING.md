# CyCentra 360 Agent — Troubleshooting Guide

Agent issues fall into three stages: **download**, **registration** (port 1515), and **connection** (port 1514).
Identify which stage is failing before taking action.

---

## Quick Diagnostics

### Test port reachability first (run on the endpoint)

```bash
# Registration port (authd)
nc -zv <MANAGER_IP> 1515

# Communication port (remoted)
nc -zv <MANAGER_IP> 1514
```

Both must succeed. If either times out, the issue is network/firewall, not the agent config.

### Check agent status on the server

```bash
ssh -p 2026 root@<SERVER_IP> "/var/ossec/bin/agent_control -l"
```

| Status | Meaning |
|---|---|
| **Active** | Agent connected and sending heartbeats |
| **Never connected** | Registered but never established port 1514 connection |
| **Disconnected** | Was active, lost connection (key mismatch or network drop) |

---

## Issue: Package Download Fails (404)

**Symptom:**
```
curl: (56) The requested URL returned error: 404
✗ Download failed: https://cy360.DOMAIN.com/agent-packages/cy360-agent-X.X.X-arm64.pkg
```

**Cause:** Packages not yet seeded on the server after an update.

**Fix:** Run `--update` on the server to seed packages from the release bundle:
```bash
ssh -p 2026 root@<SERVER_IP> "cd /opt/cycentra && bash cycentra-setup.sh --update"
```

**Verify packages exist:**
```bash
ssh -p 2026 root@<SERVER_IP> "ls -lh /var/lib/cycentra-agent-packages/"
```

---

## Issue: Agent Registered but Shows "Never connected"

**Symptom:** Agent appears in server UI with "Never connected" status immediately after install.

**Root cause:** `ossec.conf` has wrong manager address — typically the Cloudflare-proxied hostname
instead of the direct server IP. Cloudflare does not proxy TCP ports 1514/1515.

**Diagnose on the endpoint:**

macOS:
```bash
sudo grep -A3 "<server>" /Library/Ossec/etc/ossec.conf
sudo tail -20 /Library/Ossec/logs/ossec.log
```

Linux:
```bash
sudo grep -A3 "<server>" /var/ossec/etc/ossec.conf
sudo tail -20 /var/ossec/logs/ossec.log
```

**If address shows a hostname** (e.g. `cysiem.domain.com`) instead of the server IP:

macOS:
```bash
sudo sed -i '' 's|<address>.*</address>|<address>SERVER_IP</address>|' /Library/Ossec/etc/ossec.conf
sudo /Library/Ossec/bin/wazuh-control restart
```

Linux:
```bash
sudo sed -i 's|<address>.*</address>|<address>SERVER_IP</address>|' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

Windows (edit `C:\Program Files (x86)\ossec-agent\ossec.conf`):
```xml
<server>
  <address>SERVER_IP</address>
  ...
</server>
```
Then restart: `NET STOP Wazuh && NET START Wazuh`

**Server-side permanent fix:** Ensure `CY360_PUBLIC_IP` is set in `/opt/cycentra/.env`.
The setup script auto-detects and writes this on every `--update`.

```bash
grep CY360_PUBLIC_IP /opt/cycentra/.env
# If missing:
echo "CY360_PUBLIC_IP=$(curl -fsSL https://ifconfig.me)" >> /opt/cycentra/.env
systemctl restart cycentra
```

---

## Issue: Registration Fails ("Invalid request" or "Unable to connect to enrollment service")

**Symptom (IPv6 error):**
```
ERROR: (1208): Unable to connect to enrollment service at '[2606:4700:...]:1515'
```

**Cause:** The manager hostname resolves to a Cloudflare IPv6 address. Wazuh ports are TCP
and not proxied by Cloudflare.

**Fix:** Use the server's direct IP:
```bash
# macOS
sudo /Library/Ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)"
sudo /Library/Ossec/bin/wazuh-control restart

# Linux
sudo /var/ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)"
sudo systemctl restart wazuh-agent
```

---

## Issue: Agent Shows "Disconnected" (Was Previously Active)

**Cause:** Key mismatch. The agent's `client.keys` no longer matches the server's record —
usually caused by reinstalling the agent without removing the old server entry first.

**Check on server:**
```bash
ssh -p 2026 root@<SERVER_IP> "tail -20 /var/ossec/logs/ossec.log | grep -i 'error\|key\|agent'"
```

**Fix:**

Step 1 — Remove stale entry on server:
```bash
ssh -p 2026 root@<SERVER_IP> "echo 'y' | /var/ossec/bin/manage_agents -r AGENT_ID"
```

Step 2 — Re-register on endpoint:

macOS:
```bash
sudo /Library/Ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)"
sudo /Library/Ossec/bin/wazuh-control restart
```

Linux:
```bash
sudo /var/ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)"
sudo systemctl restart wazuh-agent
```

---

## Issue: Installer Runs but No Output After "Installing (PKG/RPM/DEB)"

**Cause on RPM:** Package already installed at same version — `rpm -ihv` fails silently.
The installer now uses `-Uvh` as fallback (upgrade mode).

**Cause on PKG (macOS):** Upgrade path skips registration. The installer now calls
`agent-auth` explicitly after the PKG completes.

**Manual re-registration:**
```bash
# macOS
sudo /Library/Ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)" && \
sudo /Library/Ossec/bin/wazuh-control restart

# Linux
sudo /var/ossec/bin/agent-auth -m SERVER_IP -A "$(hostname -s)" && \
sudo systemctl restart wazuh-agent
```

---

## Log File Locations

| OS | Agent log | ossec.conf |
|---|---|---|
| macOS | `/Library/Ossec/logs/ossec.log` | `/Library/Ossec/etc/ossec.conf` |
| Linux | `/var/ossec/logs/ossec.log` | `/var/ossec/etc/ossec.conf` |
| Windows | `C:\Program Files (x86)\ossec-agent\ossec.log` | `C:\Program Files (x86)\ossec-agent\ossec.conf` |

**Server-side logs:**
```bash
ssh -p 2026 root@<SERVER_IP> "tail -50 /var/ossec/logs/ossec.log"
```

---

## Checking Agent Status on the Endpoint

macOS / Linux:
```bash
# Is the process running?
sudo /Library/Ossec/bin/wazuh-control status   # macOS
sudo systemctl status wazuh-agent               # Linux

# Does it have a valid key?
sudo cat /Library/Ossec/etc/client.keys         # macOS — should NOT be empty
sudo cat /var/ossec/etc/client.keys             # Linux

# What manager is it configured to use?
grep -A3 "<server>" /Library/Ossec/etc/ossec.conf   # macOS
grep -A3 "<server>" /var/ossec/etc/ossec.conf        # Linux
```

Windows (elevated PowerShell):
```powershell
Get-Service Wazuh
Get-Content "C:\Program Files (x86)\ossec-agent\client.keys"
```

---

## Server-Side Agent Management

```bash
# List all agents and status
/var/ossec/bin/agent_control -l

# Show detail for a specific agent
/var/ossec/bin/agent_control -i AGENT_ID

# Remove a stale agent entry (then re-register on endpoint)
echo 'y' | /var/ossec/bin/manage_agents -r AGENT_ID

# Restart Wazuh manager (needed after removing agents)
/var/ossec/bin/wazuh-control restart
```

---

## Architecture Reference

```
Endpoint                    Server (77.42.75.20)
────────                    ────────────────────
agent-auth ──── port 1515 ──→ wazuh-authd   (registration, one-time)
wazuh-agentd ── port 1514 ──→ wazuh-remoted (ongoing encrypted comms)
```

**Critical:** Both ports must be reachable using the **direct server IP**, not a
Cloudflare-proxied hostname. Cloudflare only proxies HTTP/HTTPS (80/443).
