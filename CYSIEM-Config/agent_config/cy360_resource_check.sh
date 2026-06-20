#!/usr/bin/env bash
# CyCentra 360 — Agent resource utilization monitor
# Runs every 5 min via Wazuh agent.conf (log_format=full_command).
# Emits one JSON line per threshold breach; silent when all metrics are below threshold.
# Thresholds: CPU >90%  Memory >90%  Disk (/) >85%

CPU_THRESH=90
MEM_THRESH=90
DISK_THRESH=85

H=$(hostname -s 2>/dev/null || echo "unknown")
T=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")

# CPU — instantaneous snapshot from /proc/stat (Linux) or top -l (macOS)
if [ -r /proc/stat ]; then
    CPU=$(awk '/^cpu /{idle=$5; total=0; for(i=2;i<=NF;i++) total+=$i; printf "%d", (total-idle)*100/total; exit}' /proc/stat 2>/dev/null || echo 0)
else
    CPU=$(top -l 1 -n 0 2>/dev/null | awk '/^CPU usage/{gsub(/%/,""); printf "%d", $3+$5; exit}' || echo 0)
fi

# Memory — from /proc/meminfo (Linux) or vm_stat (macOS)
if [ -r /proc/meminfo ]; then
    MEM=$(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{if(t>0) printf "%d", (t-a)*100/t; else print 0}' /proc/meminfo 2>/dev/null || echo 0)
else
    PAGE=$(vm_stat 2>/dev/null | awk '/page size of/{print $8}'); PAGE=${PAGE:-4096}
    MEM=$(vm_stat 2>/dev/null | awk -v ps="$PAGE" '
        /Pages active/{act=$3} /Pages inactive/{inc=$3}
        /Pages wired/{wir=$3} /Pages free/{fr=$3}
        END{gsub(/\./,"",act); gsub(/\./,"",inc); gsub(/\./,"",wir); gsub(/\./,"",fr);
            tot=act+inc+wir+fr; if(tot>0) printf "%d",(act+wir)*100/tot; else print 0}' || echo 0)
fi

# Disk — root filesystem
DISK=$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5+0}' || echo 0)

# Emit JSON only when a threshold is crossed
[ "${CPU:-0}" -ge "$CPU_THRESH" ]  && printf '{"event":"high_cpu","cpu_percent":%s,"threshold":%s,"host":"%s","ts":"%s"}\n'  "$CPU"  "$CPU_THRESH"  "$H" "$T"
[ "${MEM:-0}" -ge "$MEM_THRESH" ]  && printf '{"event":"high_memory","mem_percent":%s,"threshold":%s,"host":"%s","ts":"%s"}\n' "$MEM"  "$MEM_THRESH"  "$H" "$T"
[ "${DISK:-0}" -ge "$DISK_THRESH" ] && printf '{"event":"high_disk","disk_percent":%s,"threshold":%s,"host":"%s","ts":"%s"}\n'  "$DISK" "$DISK_THRESH" "$H" "$T"
