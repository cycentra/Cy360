/*
 * CyCentra 360 — CyEDR Bundled YARA Rules
 * Covers: ransomware, credential dumpers, C2 frameworks, web shells,
 *         process injection, reverse shells, coin miners, RATs
 *
 * Rule naming: CyCentra_<Category>_<Name>
 * All strings use nocase where applicable to reduce evasion via casing.
 */

// ── Credential Dumpers ────────────────────────────────────────────────────────

rule CyCentra_Mimikatz
{
    meta:
        description = "Detects Mimikatz credential dumper artifacts"
        severity    = "critical"
        category    = "credential_dumper"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "lsadump::dcsync" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "mimikatz" nocase
        $s6 = "gentilkiwi" nocase
        $bin1 = { 6D 69 6D 69 6B 61 74 7A }

    condition:
        any of them
}

rule CyCentra_LaZagne
{
    meta:
        description = "Detects LaZagne credential recovery tool"
        severity    = "high"
        category    = "credential_dumper"

    strings:
        $s1 = "lazagne" nocase
        $s2 = "LaZagne Project" nocase
        $s3 = "passwords recovered" nocase

    condition:
        2 of them
}

// ── C2 Frameworks ─────────────────────────────────────────────────────────────

rule CyCentra_CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon artifacts"
        severity    = "critical"
        category    = "c2_framework"

    strings:
        $s1 = "ReflectiveLoader" fullword
        $s2 = "%s (admin)" fullword
        $s3 = "beacon.dll" nocase
        $s4 = "cobaltstrike" nocase
        $b1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $b2 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }

    condition:
        ($b1 or $b2) or (2 of ($s*))
}

rule CyCentra_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter payload artifacts"
        severity    = "critical"
        category    = "c2_framework"

    strings:
        $s1 = "meterpreter" nocase
        $s2 = "Metasploit" nocase
        $s3 = "reverse_tcp" nocase
        $s4 = "shell_reverse_tcp" nocase
        $s5 = "stdapi_sys_config_getuid" fullword
        $b1 = { 6D 65 74 65 72 70 72 65 74 65 72 }

    condition:
        2 of them
}

rule CyCentra_EmpireFramework
{
    meta:
        description = "Detects PowerShell Empire C2 framework artifacts"
        severity    = "high"
        category    = "c2_framework"

    strings:
        $s1 = "powershell/empire" nocase
        $s2 = "EmPyre" nocase
        $s3 = "BC-SECURITY/Empire" nocase
        $s4 = "empire_key" nocase

    condition:
        any of them
}

// ── Ransomware ────────────────────────────────────────────────────────────────

rule CyCentra_Ransomware_Generic
{
    meta:
        description = "Detects generic ransomware indicators (ransom notes, encryption markers)"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "All your files are encrypted" nocase
        $note3 = "your personal files are encrypted" nocase
        $note4 = "send us bitcoin" nocase
        $note5 = "decrypt your files" nocase
        $note6 = "HOW TO RECOVER YOUR FILES" nocase
        $note7 = "README_FOR_DECRYPT" nocase
        $note8 = "HELP_DECRYPT" nocase
        $ext1  = ".locked" nocase
        $ext2  = ".encrypted" nocase
        $ext3  = ".crypted" nocase

    condition:
        2 of ($note*) or 3 of ($ext*)
}

rule CyCentra_LockBit
{
    meta:
        description = "Detects LockBit ransomware artifacts"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $s1 = "LockBit" nocase
        $s2 = "lockbit_note" nocase
        $s3 = "Restore-My-Files.txt" nocase
        $s4 = ".lockbit" nocase

    condition:
        2 of them
}

rule CyCentra_Conti_Ryuk
{
    meta:
        description = "Detects Conti and Ryuk ransomware artifacts"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $s1 = "CONTI" fullword nocase
        $s2 = "RyukReadMe" nocase
        $s3 = "No system is safe" nocase
        $s4 = "CONTI_LOCKER" nocase

    condition:
        any of them
}

// ── Web Shells ────────────────────────────────────────────────────────────────

rule CyCentra_WebShell_PHP
{
    meta:
        description = "Detects PHP web shell patterns"
        severity    = "high"
        category    = "webshell"

    strings:
        $php    = "<?php"
        $eval1  = "eval(base64_decode(" nocase
        $eval2  = "eval(gzinflate(base64_decode(" nocase
        $eval3  = "eval(str_rot13(" nocase
        $system = "system($_" nocase
        $exec   = "exec($_" nocase
        $shell  = "shell_exec($_" nocase
        $pass   = "$_POST['pass']" nocase
        $cmd    = "$_GET['cmd']" nocase
        $china  = "China Chopper" nocase

    condition:
        $php and (2 of ($eval*) or 2 of ($system, $exec, $shell, $pass, $cmd) or $china)
}

rule CyCentra_WebShell_ASPX
{
    meta:
        description = "Detects ASPX/ASP web shell patterns"
        severity    = "high"
        category    = "webshell"

    strings:
        $s1 = "<%@ Page" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "Process.Start" nocase
        $s4 = "Shell.Application" nocase
        $s5 = "WScript.Shell" nocase
        $s6 = "eval(Request" nocase

    condition:
        $s1 and (2 of ($s2, $s3, $s4, $s5, $s6))
}

// ── Process Injection ─────────────────────────────────────────────────────────

rule CyCentra_Process_Injection_Win32
{
    meta:
        description = "Detects Windows process injection API call sequences"
        severity    = "high"
        category    = "process_injection"

    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "WriteProcessMemory" fullword
        $api3 = "CreateRemoteThread" fullword
        $api4 = "OpenProcess" fullword
        $api5 = "NtCreateThreadEx" fullword
        $api6 = "RtlCreateUserThread" fullword

    condition:
        3 of them
}

rule CyCentra_Reflective_DLL_Injection
{
    meta:
        description = "Detects reflective DLL injection technique"
        severity    = "high"
        category    = "process_injection"

    strings:
        $s1 = "ReflectiveLoader" fullword
        $b1 = { 55 8B EC 83 EC ?? 53 56 57 }
        $b2 = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 }

    condition:
        $s1 or ($b1 and $b2)
}

// ── Reverse Shells ────────────────────────────────────────────────────────────

rule CyCentra_ReverseShell_Bash
{
    meta:
        description = "Detects bash reverse shell one-liners"
        severity    = "high"
        category    = "reverse_shell"

    strings:
        $s1 = "bash -i >& /dev/tcp/" nocase
        $s2 = "bash -c 'bash -i >& /dev/tcp/" nocase
        $s3 = "0>&1" nocase
        $s4 = "/dev/tcp/" nocase

    condition:
        ($s1 or $s2) and ($s3 or $s4)
}

rule CyCentra_ReverseShell_Python
{
    meta:
        description = "Detects Python reverse shell code"
        severity    = "high"
        category    = "reverse_shell"

    strings:
        $s1 = "socket.SOCK_STREAM" nocase
        $s2 = "socket.connect(" nocase
        $s3 = "os.dup2(s.fileno()" nocase
        $s4 = "subprocess.call([\"/bin/sh\"" nocase
        $s5 = "pty.spawn" nocase

    condition:
        3 of them
}

// ── Obfuscated PowerShell ─────────────────────────────────────────────────────

rule CyCentra_PowerShell_Obfuscated
{
    meta:
        description = "Detects heavily obfuscated PowerShell execution patterns"
        severity    = "high"
        category    = "obfuscation"

    strings:
        $s1 = "powershell" nocase
        $b64_1 = "-EncodedCommand" nocase
        $b64_2 = "-enc " nocase
        $b64_3 = "[System.Convert]::FromBase64String(" nocase
        $bypass1 = "-ExecutionPolicy Bypass" nocase
        $bypass2 = "-Exec Bypass" nocase
        $iex1    = "IEX(" nocase
        $iex2    = "Invoke-Expression" nocase
        $dl      = "(New-Object Net.WebClient).DownloadString(" nocase

    condition:
        $s1 and (
            ($b64_1 or $b64_2 or $b64_3) or
            (($bypass1 or $bypass2) and ($iex1 or $iex2 or $dl))
        )
}

// ── Coin Miners ───────────────────────────────────────────────────────────────

rule CyCentra_CryptoMiner_XMRig
{
    meta:
        description = "Detects XMRig Monero cryptocurrency miner"
        severity    = "medium"
        category    = "coinminer"

    strings:
        $s1 = "xmrig" nocase
        $s2 = "monero" nocase
        $s3 = "stratum+tcp://" nocase
        $s4 = "\"donate-level\"" nocase
        $s5 = "\"threads\"" nocase
        $s6 = "pool.minexmr.com" nocase
        $s7 = "xmrpool.eu" nocase

    condition:
        2 of them
}

rule CyCentra_CryptoMiner_Generic
{
    meta:
        description = "Detects generic cryptocurrency miner artifacts"
        severity    = "medium"
        category    = "coinminer"

    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "--cpu-max-threads-hint" nocase
        $s4 = "nicehash" nocase
        $s5 = "--coin xmr" nocase

    condition:
        2 of them
}

// ── Remote Access Trojans ─────────────────────────────────────────────────────

rule CyCentra_RAT_AsyncRAT
{
    meta:
        description = "Detects AsyncRAT remote access trojan"
        severity    = "critical"
        category    = "rat"

    strings:
        $s1 = "AsyncRAT" nocase
        $s2 = "Async-RAT" nocase
        $s3 = "HVNC" fullword
        $s4 = "AsyncClient" fullword

    condition:
        2 of them
}

rule CyCentra_RAT_NjRAT
{
    meta:
        description = "Detects NjRAT / Bladabindi remote access trojan"
        severity    = "critical"
        category    = "rat"

    strings:
        $s1 = "njRAT" nocase
        $s2 = "Bladabindi" nocase
        $s3 = "nj-RAT" nocase
        $s4 = { 6E 6A 72 61 74 }

    condition:
        any of them
}

// ── Privilege Escalation ──────────────────────────────────────────────────────

rule CyCentra_PrivEsc_SudoAbuse
{
    meta:
        description = "Detects common sudo privilege escalation abuse patterns"
        severity    = "high"
        category    = "privilege_escalation"

    strings:
        $s1 = "sudo -l" nocase
        $s2 = "sudo bash" nocase
        $s3 = "sudo /bin/bash" nocase
        $s4 = "chmod +s /bin/bash" nocase
        $s5 = "chmod u+s /bin/bash" nocase
        $s6 = "SUID bash" nocase

    condition:
        2 of them
}

rule CyCentra_PrivEsc_SUID_Bit
{
    meta:
        description = "Detects SUID bit manipulation for privilege escalation"
        severity    = "high"
        category    = "privilege_escalation"

    strings:
        $s1 = "chmod +s" nocase
        $s2 = "chmod 4755" nocase
        $s3 = "chmod 4777" nocase
        $s4 = "find / -perm -u=s" nocase
        $s5 = "find / -perm /4000" nocase

    condition:
        2 of them
}

// ── Persistence ───────────────────────────────────────────────────────────────

rule CyCentra_Persistence_Crontab
{
    meta:
        description = "Detects suspicious crontab-based persistence"
        severity    = "medium"
        category    = "persistence"

    strings:
        $s1 = "crontab -e" nocase
        $s2 = "/etc/cron." nocase
        $s3 = "curl | bash" nocase
        $s4 = "wget | bash" nocase
        $s5 = "curl | sh" nocase
        $s6 = "wget | sh" nocase

    condition:
        ($s1 or $s2) and ($s3 or $s4 or $s5 or $s6)
}

rule CyCentra_Persistence_LaunchDaemon_Abuse
{
    meta:
        description = "Detects suspicious LaunchDaemon/LaunchAgent persistence on macOS"
        severity    = "medium"
        category    = "persistence"

    strings:
        $s1 = "LaunchDaemons" nocase
        $s2 = "LaunchAgents" nocase
        $s3 = "ProgramArguments" nocase
        $s4 = "RunAtLoad" nocase
        $bash = "/bin/bash" nocase
        $sh   = "/bin/sh" nocase
        $curl = "curl" nocase
        $wget = "wget" nocase

    condition:
        ($s1 or $s2) and $s3 and $s4 and ($bash or $sh) and ($curl or $wget)
}
