#Requires -Version 5.1
<#
.SYNOPSIS
    CyCentra 360 — CyEDR Agent Installer for Windows

.DESCRIPTION
    Installs CyEDR on Windows endpoints:
     • Sysmon64 with cycentra_sysmon_config.xml
     • YARA for on-demand file scanning
     • PowerShell Script Block Logging
     • CyEDR Python bridge daemon (Windows service via NSSM or sc.exe)

.PARAMETER Token
    Deployment token (required)

.PARAMETER Platform
    CyCentra 360 platform URL, e.g. https://cy360.example.com (required)

.PARAMETER AssetType
    Asset classification: workstation|server|database|domain_controller|api_gateway|jump_server
    Default: workstation

.PARAMETER Silent
    Non-interactive mode

.PARAMETER WithTray
    Switch: install the CyEDR system-tray app even on non-workstation asset types

.PARAMETER NoTray
    Switch: skip installing the system-tray app

.EXAMPLE
    iex ((New-Object Net.WebClient).DownloadString('https://cy360.example.com/api/edr/installer/win'))

.EXAMPLE
    .\cyedr-install.ps1 -Token "eyJ..." -Platform "https://cy360.example.com"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [string]$Platform,

    [ValidateSet("workstation","server","database","domain_controller","api_gateway","jump_server")]
    [string]$AssetType = "workstation",

    [switch]$WithTray,
    [switch]$NoTray,
    [switch]$Silent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# ── Paths ─────────────────────────────────────────────────────────────────────
$EdrHome   = "C:\Program Files\CyCentra\edr"
$SysmonDir = "C:\Program Files\CyCentra\sysmon"
$LogFile   = "$EdrHome\logs\cyedr_agent.log"
$Platform  = $Platform.TrimEnd("/")
# Separate from $EdrHome on purpose: Set-AntiTamper below strips ALL access for
# BUILTIN\Users on $EdrHome (it holds config.json's enrollment token), which
# would make the tray binary unreadable/unrunnable for a standard user. This
# sibling directory inherits Program Files' default ACL (Users: Read & Execute)
# instead. The agent's IPC token/pipe live in yet another sibling, edr-ipc —
# see Config.ipc_dir's default in cyedr_agent.py — created by the agent
# itself at startup, not by this installer.
$TrayHome  = "C:\Program Files\CyCentra\edr-tray"

# ── Architecture detection ─────────────────────────────────────────────────────
$EdrArch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-CyInfo  { param($m) Write-Host "[CyEDR] $m"  -ForegroundColor Cyan }
function Write-CyOk    { param($m) Write-Host "[CyEDR] $m"  -ForegroundColor Green }
function Write-CyWarn  { param($m) Write-Host "[CyEDR] WARN: $m" -ForegroundColor Yellow }
function Write-CyError { param($m) Write-Host "[CyEDR] ERROR: $m" -ForegroundColor Red; exit 1 }

function Download-File {
    param([string]$Url, [string]$Dest, [hashtable]$Headers = @{})
    $headers = @{ "Authorization" = "Bearer $Token" } + $Headers
    Invoke-WebRequest -Uri $Url -OutFile $Dest -Headers $headers -UseBasicParsing -TimeoutSec 120
}

function Invoke-ApiJson {
    param([string]$Method = "GET", [string]$Uri, [string]$Body = "")
    $headers = @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" }
    if ($Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body -UseBasicParsing
    } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -UseBasicParsing
    }
}

# ── Admin check ────────────────────────────────────────────────────────────────
function Assert-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-CyError "This script must run as Administrator. Right-click PowerShell → 'Run as Administrator'."
    }
    Write-CyInfo "Running as Administrator — OK"
}

# ── Create directories ─────────────────────────────────────────────────────────
function Initialize-Directories {
    Write-CyInfo "Creating CyEDR directories..."
    foreach ($d in @($EdrHome, "$EdrHome\logs", "$EdrHome\quarantine", "$EdrHome\ioc_cache",
                     "$EdrHome\yara_rules", $SysmonDir)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    # Restrict access to SYSTEM and Administrators only
    $acl = Get-Acl $EdrHome
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule2)
    Set-Acl -Path $EdrHome -AclObject $acl
    Write-CyOk "Directories created"
}

# ── Download standalone CyEDR binary (PyInstaller, no Python needed) ───────────
function Install-EdrBinary {
    param([string]$Arch)
    Write-CyInfo "Downloading CyEDR agent binary ($Arch)..."
    $binDest = "$EdrHome\cyedr-agent.exe"

    # Try platform MSI first (enterprise/MDM path)
    $msiPath = "$env:TEMP\cyedr-agent-$Arch.msi"
    try {
        Download-File -Url "$Platform/edr-packages/cyedr-agent-latest-$Arch.msi" -Dest $msiPath
        Write-CyInfo "Installing CyEDR MSI package..."
        $r = Start-Process "msiexec.exe" `
            -ArgumentList "/i `"$msiPath`" /qn /l*v `"$EdrHome\logs\msi-install.log`"" `
            -Wait -PassThru -NoNewWindow
        Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
        if ($r.ExitCode -eq 0) { Write-CyOk "CyEDR MSI installed"; return }
        Write-CyWarn "MSI exit code $($r.ExitCode) — falling back to binary download"
    } catch {
        Write-CyWarn "MSI download unavailable ($($_.Exception.Message)) — using binary bundle..."
    }

    # Fallback: download PyInstaller one-file exe directly
    Download-File -Url "$Platform/api/edr/installer/agent-bundle?os=WINDOWS&arch=$Arch" `
        -Dest $binDest
    Write-CyOk "CyEDR agent binary downloaded → $binDest"
}

# ── Download CyEDR system-tray binary ───────────────────────────────────────────
function Install-TrayBinary {
    param([string]$Arch)
    if ($NoTray) {
        Write-CyInfo "System-tray install skipped (-NoTray)."
        return $null
    }
    if (-not $WithTray -and $AssetType -ne "workstation") {
        Write-CyInfo "System-tray install skipped (asset type '$AssetType' is not workstation; pass -WithTray to force)."
        return $null
    }
    Write-CyInfo "Downloading CyEDR system-tray binary ($Arch)..."
    New-Item -ItemType Directory -Path $TrayHome -Force | Out-Null
    $trayExe = "$TrayHome\cyedr-tray.exe"
    try {
        Download-File -Url "$Platform/api/edr/installer/tray-bundle?os=WINDOWS&arch=$Arch" -Dest $trayExe
        Write-CyOk "System-tray binary downloaded -> $trayExe"
        return $trayExe
    } catch {
        Write-CyWarn "Tray binary not available for WINDOWS/$Arch ($($_.Exception.Message)) — skipping tray install"
        return $null
    }
}

# ── Register tray auto-start for every user, at logon ───────────────────────────
function Install-TrayScheduledTask {
    param([string]$TrayExe)
    Write-CyInfo "Registering CyEDR tray auto-start (any user, at logon)..."
    try {
        Unregister-ScheduledTask -TaskName "CyEDR Tray" -Confirm:$false -ErrorAction SilentlyContinue
        $action    = New-ScheduledTaskAction -Execute $TrayExe
        # No -User on the trigger + a GroupId principal: this fires for ANY
        # user's logon and the task runs in that user's own session/token —
        # not as a fixed service account. Well-known pattern for per-user
        # startup tasks registered once machine-wide.
        $trigger   = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName "CyEDR Tray" -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
        Write-CyOk "Tray scheduled task registered (starts for any user at logon)"
    } catch {
        Write-CyWarn "Could not register tray scheduled task: $_"
    }
}

# ── Install Sysmon ─────────────────────────────────────────────────────────────
function Install-Sysmon {
    Write-CyInfo "Installing Sysmon64..."

    # Download Sysmon from platform (pre-bundled in CyCentra)
    $sysmonExe    = "$SysmonDir\Sysmon64.exe"
    $sysmonConfig = "$SysmonDir\cycentra_sysmon_config.xml"

    try {
        Download-File -Url "$Platform/api/edr/installer/sysmon-exe" -Dest $sysmonExe
    } catch {
        # Fallback: Download from Sysinternals
        Write-CyWarn "Platform Sysmon bundle unavailable — downloading from Sysinternals..."
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
            -OutFile "$SysmonDir\Sysmon.zip" -UseBasicParsing -TimeoutSec 120
        Expand-Archive -Path "$SysmonDir\Sysmon.zip" -DestinationPath $SysmonDir -Force
        Remove-Item "$SysmonDir\Sysmon.zip" -Force
    }

    # Download CyCentra Sysmon config
    try {
        Download-File -Url "$Platform/api/edr/installer/sysmon-config" -Dest $sysmonConfig
    } catch {
        Write-CyWarn "Could not download sysmon config from platform — using embedded config"
        # Minimal embedded config (full config comes from platform)
        @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Out-File -FilePath $sysmonConfig -Encoding UTF8
    }

    # Install or update Sysmon
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-CyInfo "Updating existing Sysmon config..."
        & $sysmonExe -c $sysmonConfig 2>&1 | Out-Null
    } else {
        Write-CyInfo "Installing Sysmon64..."
        & $sysmonExe -accepteula -i $sysmonConfig 2>&1 | Out-Null
    }

    Start-Sleep -Seconds 2
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-CyOk "Sysmon64 is running — event channel: Microsoft-Windows-Sysmon/Operational"
    } else {
        Write-CyWarn "Sysmon64 may not be running — check Event Viewer"
    }
}

# ── Install YARA ───────────────────────────────────────────────────────────────
function Install-Yara {
    Write-CyInfo "Installing YARA..."
    $yaraExe = "$EdrHome\yara64.exe"
    try {
        Download-File -Url "$Platform/api/edr/installer/yara-exe" -Dest $yaraExe
        Write-CyOk "YARA installed from platform"
    } catch {
        Write-CyWarn "YARA download failed — on-demand scanning will be unavailable"
    }
    # Download YARA rules
    try {
        Download-File -Url "$Platform/api/edr/installer/yara-rules" `
            -Dest "$EdrHome\yara_rules\cycentra.yar"
        Write-CyOk "YARA rules downloaded"
    } catch {
        Write-CyWarn "YARA rules download failed"
    }
}

# ── Optional nmap for Network Probe agents ────────────────────────────────────
function Install-Nmap {
    # nmap is only needed when this agent is designated as a Network Probe.
    # Install silently via winget or chocolatey if available; skip otherwise.
    $nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"
    if (Test-Path $nmapExe) {
        Write-CyOk "nmap already installed — Network Probe subnet scan ready"
        return
    }
    Write-CyInfo "Installing nmap (required for Network Probe subnet scan)..."
    $installed = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            winget install --id Insecure.Nmap --silent --accept-package-agreements `
                --accept-source-agreements 2>&1 | Out-Null
            $installed = $true
            Write-CyOk "nmap installed via winget"
        } catch { }
    }
    if (-not $installed -and (Get-Command choco -ErrorAction SilentlyContinue)) {
        try {
            choco install nmap -y --no-progress 2>&1 | Out-Null
            $installed = $true
            Write-CyOk "nmap installed via chocolatey"
        } catch { }
    }
    if (-not $installed) {
        Write-CyWarn "nmap not installed — Network Probe subnet scan unavailable. Install manually: https://nmap.org/download.html"
    }
}

# ── PowerShell Script Block Logging ───────────────────────────────────────────
function Enable-PSLogging {
    Write-CyInfo "Enabling PowerShell Script Block Logging..."
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
    Write-CyOk "PowerShell Script Block Logging enabled (EventID 4104 → channel Microsoft-Windows-PowerShell/Operational)"
}

# ── Write CyEDR config.json ────────────────────────────────────────────────────
function Deploy-Agent {
    Write-CyInfo "Writing CyEDR agent config..."

    # Write config
    $hostname  = $env:COMPUTERNAME
    $agentIp   = (Get-NetIPAddress -AddressFamily IPv4 |
                  Where-Object { $_.InterfaceAlias -notmatch "Loopback" } |
                  Select-Object -First 1).IPAddress
    $cfgObj = @{
        platform_url       = $Platform
        deploy_token       = $Token
        asset_type         = $AssetType
        hostname           = $hostname
        os_type            = "WINDOWS"
        edr_home           = $EdrHome
        poll_interval      = 60
        heartbeat_interval = 60
        telemetry_batch    = 20
        yara_binary        = "$EdrHome\yara64.exe"
        yara_rules         = "$EdrHome\yara_rules\cycentra.yar"
        quarantine_dir     = "$EdrHome\quarantine"
        ioc_cache          = "$EdrHome\ioc_cache\ioc.json"
        log_file           = $LogFile
        sysmon_channel     = "Microsoft-Windows-Sysmon/Operational"
    }
    $cfgObj | ConvertTo-Json -Depth 5 | Out-File -FilePath "$EdrHome\config.json" -Encoding UTF8

    Write-CyOk "Agent deployed to $EdrHome"
}

# ── Enroll with platform ───────────────────────────────────────────────────────
function Invoke-Enrollment {
    Write-CyInfo "Enrolling with CyCentra 360 platform..."
    $hostname = $env:COMPUTERNAME
    $agentIp  = (Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.InterfaceAlias -notmatch "Loopback" } |
                 Select-Object -First 1).IPAddress

    # Detect default gateway MAC at install time (trusted corporate environment).
    # Seeds network zone auto-learning so the server can auto-suggest approval.
    $gwIp  = ""
    $gwMac = ""
    try {
        $gwIp = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric |
                 Select-Object -First 1).NextHop
        if ($gwIp) {
            $neighbor = Get-NetNeighbor -IPAddress $gwIp -ErrorAction SilentlyContinue |
                        Select-Object -First 1
            if ($neighbor) {
                $gwMac = $neighbor.LinkLayerAddress.ToUpper().Replace("-", ":")
            }
        }
    } catch {
        Write-CyWarn "Could not detect gateway MAC — zone auto-learning will rely on heartbeat"
    }

    $body = @{
        hostname    = $hostname
        os_type     = "WINDOWS"
        asset_type  = $AssetType
        agent_ip    = "$agentIp"
        version     = "1.0.0"
        gateway_ip  = "$gwIp"
        gateway_mac = "$gwMac"
    } | ConvertTo-Json

    try {
        $resp = Invoke-ApiJson -Method POST -Uri "$Platform/api/edr/agents/self-enroll" -Body $body
        $agentId = $resp.agent_id
        $enrollToken = $resp.enrollment_token
        if (-not $agentId) { Write-CyError "Enrollment response missing agent_id: $resp" }
        if (-not $enrollToken) { Write-CyError "Enrollment response missing enrollment_token: $resp" }

        # Update config with agent_id AND the per-agent enrollment_token — without the
        # latter, the agent falls back to the shared deploy_token for heartbeat/telemetry
        # auth, which never matches the server's per-agent token and 401s permanently.
        $cfg = Get-Content "$EdrHome\config.json" | ConvertFrom-Json
        $cfg | Add-Member -NotePropertyName "agent_id" -NotePropertyValue $agentId -Force
        $cfg | Add-Member -NotePropertyName "enrollment_token" -NotePropertyValue $enrollToken -Force
        $cfg | ConvertTo-Json -Depth 5 | Out-File -FilePath "$EdrHome\config.json" -Encoding UTF8

        Write-CyOk "Enrolled — Agent ID: $agentId"
    } catch {
        Write-CyError "Enrollment failed: $_"
    }
}

# ── Install Windows Service ────────────────────────────────────────────────────
function Install-WindowsService {
    Write-CyInfo "Installing CyEDR Windows service..."

    $agentExe    = "$EdrHome\cyedr-agent.exe"
    $svcName     = "CyEDRAgent"
    $displayName = "CyCentra 360 EDR Agent"
    $description = "CyCentra 360 endpoint detection and response agent"

    # Remove existing service if present
    $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        sc.exe delete $svcName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Skip service creation if the MSI already installed it
    $afterMsi = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($afterMsi) {
        Write-CyOk "Service '$svcName' already present (installed by MSI)"
        return
    }

    # Try NSSM first (proper service wrapper), fallback to sc.exe
    $nssm = Get-Command "nssm" -ErrorAction SilentlyContinue
    if ($nssm) {
        Write-CyInfo "Using NSSM to create service..."
        & nssm install $svcName $agentExe "--config `"$EdrHome\config.json`""
        & nssm set $svcName DisplayName  $displayName
        & nssm set $svcName Description  $description
        & nssm set $svcName AppDirectory $EdrHome
        & nssm set $svcName AppStdout    $LogFile
        & nssm set $svcName AppStderr    $LogFile
        & nssm set $svcName Start        SERVICE_AUTO_START
        & nssm set $svcName AppRestartDelay 10000
    } else {
        $binPath = "`"$agentExe`" --config `"$EdrHome\config.json`""
        sc.exe create $svcName binPath= $binPath start= auto DisplayName= $displayName | Out-Null
        sc.exe description $svcName $description | Out-Null
        sc.exe failure $svcName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
    }

    sc.exe config $svcName start= delayed-auto | Out-Null
    Write-CyOk "Windows service '$svcName' created"
}

# ── Anti-tamper: protect CyEDR files ──────────────────────────────────────────
function Set-AntiTamper {
    Write-CyInfo "Applying anti-tamper protections..."

    # Prevent non-admin processes from writing to EDR home
    $acl = Get-Acl $EdrHome
    $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Users", "Write,Delete,Modify",
        "ContainerInherit,ObjectInherit", "None", "Deny")
    $acl.AddAccessRule($deny)
    Set-Acl -Path $EdrHome -AclObject $acl

    # Windows Event Log: log CyEDR service tamper attempts
    # Rule 101031 in cy_cust_rules.xml will fire on service stop events
    Write-CyOk "Anti-tamper ACLs applied"
}

# ── Start service ──────────────────────────────────────────────────────────────
function Start-CyEDRService {
    Write-CyInfo "Starting CyEDR agent service..."
    Start-Service -Name "CyEDRAgent" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name "CyEDRAgent" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-CyOk "CyEDRAgent service is running"
    } else {
        Write-CyWarn "Service may not be running — check: Get-EventLog Application -Source CyEDRAgent"
    }
}

# ── Summary ────────────────────────────────────────────────────────────────────
function Show-Summary {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host " CyEDR Agent Installation Complete                    " -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Platform:   $Platform"
    Write-Host "  Agent home: $EdrHome"
    Write-Host "  Logs:       $LogFile"
    Write-Host ""
    Write-Host "  Status: Get-Service CyEDRAgent" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Sysmon is active: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
    if (Test-Path "$TrayHome\cyedr-tray.exe") {
        Write-Host ""
        Write-Host "  Tray:       $TrayHome\cyedr-tray.exe (starts automatically at next logon, any user)" -ForegroundColor Cyan
        # Printed here permanently, not only inside the tray's dialogs — by the
        # time someone needs this, the tray may be showing the unreachable/red
        # state and this may be the only place it's written down.
        Write-Host "  Restart if stopped: use `"Start CyEDR...`" in the tray menu" -ForegroundColor Cyan
        Write-Host "              (asks for the CyEDR admin password, then a Windows UAC prompt)" -ForegroundColor Cyan
        Write-Host "              or from an elevated/Administrator PowerShell:" -ForegroundColor Cyan
        Write-Host "              sc start CyEDRAgent" -ForegroundColor Cyan
    }
    Write-Host "  Next: View endpoint in CyCentra 360 > Endpoint Fleet" -ForegroundColor Yellow
    Write-Host ""
}

# ── Main ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██████╗██╗   ██╗     ███████╗██████╗ ██████╗ " -ForegroundColor Blue
Write-Host " ██╔════╝╚██╗ ██╔╝     ██╔════╝██╔══██╗██╔══██╗" -ForegroundColor Blue
Write-Host " ██║      ╚████╔╝      █████╗  ██║  ██║██████╔╝" -ForegroundColor Blue
Write-Host " ╚██████╗   ██║███████╗███████╗██████╔╝██║  ██║" -ForegroundColor Blue
Write-Host "  ╚═════╝   ╚╝╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝" -ForegroundColor Blue
Write-Host ""
Write-Host "  CyCentra 360 — CyEDR Endpoint Defense  |  FROM SIGNALS TO STRENGTH" -ForegroundColor Cyan
Write-Host "  Arch: $EdrArch" -ForegroundColor DarkGray
Write-Host ""

Assert-Admin
Initialize-Directories
Install-EdrBinary -Arch $EdrArch
Install-Sysmon
Install-Yara
Install-Nmap
Enable-PSLogging
Deploy-Agent
Set-AntiTamper
Invoke-Enrollment
Install-WindowsService
$TrayExePath = Install-TrayBinary -Arch $EdrArch
if ($TrayExePath) { Install-TrayScheduledTask -TrayExe $TrayExePath }
Start-CyEDRService
Show-Summary
