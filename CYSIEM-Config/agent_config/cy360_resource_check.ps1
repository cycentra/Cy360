# CyCentra 360 — Agent resource utilization monitor (Windows)
# Runs every 5 min via Wazuh agent.conf (log_format=full_command).
# Emits one JSON line per threshold breach; silent when all metrics are below threshold.
$ErrorActionPreference = 'SilentlyContinue'

$CPU_THRESH  = 90
$MEM_THRESH  = 90
$DISK_THRESH = 85

$H = $env:COMPUTERNAME
$T = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# CPU — average of two 1-second samples
try {
    $cpu = [math]::Round(
        (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 2 |
         Select-Object -ExpandProperty CounterSamples |
         Measure-Object CookedValue -Average).Average, 0)
} catch { $cpu = 0 }

# Memory
try {
    $os  = Get-CimInstance Win32_OperatingSystem
    $mem = [math]::Round(
        ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) /
         $os.TotalVisibleMemorySize * 100, 0)
} catch { $mem = 0 }

# Disk (C: drive)
try {
    $drv  = Get-PSDrive C
    $disk = [math]::Round($drv.Used / ($drv.Used + $drv.Free) * 100, 0)
} catch { $disk = 0 }

if ($cpu  -ge $CPU_THRESH)  { Write-Output "{`"event`":`"high_cpu`",`"cpu_percent`":$cpu,`"threshold`":$CPU_THRESH,`"host`":`"$H`",`"ts`":`"$T`"}" }
if ($mem  -ge $MEM_THRESH)  { Write-Output "{`"event`":`"high_memory`",`"mem_percent`":$mem,`"threshold`":$MEM_THRESH,`"host`":`"$H`",`"ts`":`"$T`"}" }
if ($disk -ge $DISK_THRESH) { Write-Output "{`"event`":`"high_disk`",`"disk_percent`":$disk,`"threshold`":$DISK_THRESH,`"host`":`"$H`",`"ts`":`"$T`"}" }
