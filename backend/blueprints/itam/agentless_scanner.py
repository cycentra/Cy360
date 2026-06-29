"""blueprints/itam/agentless_scanner.py — Agentless SSH/WinRM asset discovery for ITAM."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

try:
    import paramiko
    _PARAMIKO = True
except ImportError:
    _PARAMIKO = False

try:
    import winrm
    _WINRM = True
except ImportError:
    _WINRM = False

_OS_NOISE_RE = re.compile(
    r"^(libx|libgtk|locales|tzdata|ca-certificates|fonts-|adduser|base-files|coreutils|dpkg)",
    re.IGNORECASE,
)

# ── helpers ────────────────────────────────────────────────────────────────────

def _empty_result(ip: str, method: str) -> dict:
    return {
        "ip": ip,
        "method": method,
        "status": "ok",
        "os_info": {},
        "hostname": "",
        "hardware": {"cpu_cores": 0, "cpu_model": "", "ram_mb": 0, "disk_gb": 0},
        "packages": [],
        "services": [],
        "listening_ports": [],
        "local_users": [],
        "error": "",
    }


def _parse_os_release(raw: str) -> dict:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def _parse_pipe_packages(raw: str, pkg_mgr_override: str = "") -> list[dict]:
    pkgs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in raw.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4:
            if len(parts) == 2 and pkg_mgr_override == "brew":
                name = parts[0].strip()
                version = parts[1].strip() if len(parts) > 1 else ""
                arch = ""
                pm = "brew"
            else:
                continue
        else:
            name, version, arch, pm = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
        if not name:
            continue
        if _OS_NOISE_RE.match(name):
            continue
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        if pkg_mgr_override:
            pm = pkg_mgr_override
        pkgs.append({"name": name, "version": version, "vendor": "", "package_manager": pm, "architecture": arch})
    return pkgs


def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return default


# ── SSH ────────────────────────────────────────────────────────────────────────

def _ssh_run(client: Any, cmd: str) -> str:
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=15)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def ssh_deep_scan(
    ip: str,
    port: int = 22,
    username: str = "",
    password: str = "",
    key_path: str = "",
    timeout: int = 15,
) -> dict:
    if not _PARAMIKO:
        return {"error": "paramiko not installed"}

    result = _empty_result(ip, "ssh")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict[str, Any] = {
            "hostname": ip,
            "port": port,
            "username": username,
            "timeout": timeout,
            "allow_agent": False,
            "look_for_keys": bool(key_path),
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        if password:
            connect_kwargs["password"] = password
        client.connect(**connect_kwargs)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    try:
        os_raw = _ssh_run(client, "cat /etc/os-release 2>/dev/null || uname -a")
        result["hostname"] = _ssh_run(client, "hostname -f 2>/dev/null || hostname")

        if os_raw.lower().startswith("linux") or "=" not in os_raw:
            is_macos = "darwin" in os_raw.lower()
        else:
            is_macos = "darwin" in os_raw.lower()

        result["os_info"] = _parse_os_release(os_raw) if not is_macos else {"raw": os_raw}

        pkgs: list[dict] = []
        deb_raw = _ssh_run(client, "dpkg-query -W -f='${Package}|${Version}|${Architecture}|deb\\n' 2>/dev/null")
        if deb_raw:
            pkgs.extend(_parse_pipe_packages(deb_raw))

        rpm_raw = _ssh_run(client, "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{ARCH}|rpm\\n' 2>/dev/null")
        if rpm_raw:
            pkgs.extend(_parse_pipe_packages(rpm_raw))

        if is_macos:
            brew_raw = _ssh_run(client, "brew list --versions 2>/dev/null | head -200 || true")
            if brew_raw:
                brew_lines = []
                for line in brew_raw.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        brew_lines.append(f"{parts[0]}|{parts[-1]}||brew")
                    elif len(parts) == 1:
                        brew_lines.append(f"{parts[0]}|||brew")
                pkgs.extend(_parse_pipe_packages("\n".join(brew_lines), "brew"))

        seen_keys: set[tuple[str, str]] = set()
        deduped: list[dict] = []
        for p in pkgs:
            k = (p["name"].lower(), p["version"])
            if k not in seen_keys:
                seen_keys.add(k)
                deduped.append(p)
        result["packages"] = deduped

        svc_raw = _ssh_run(
            client,
            "systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null | awk '{print $1}' | head -50",
        )
        if not svc_raw and is_macos:
            svc_raw = _ssh_run(
                client,
                "launchctl list 2>/dev/null | awk 'NR>1 && $3!~/^-/{print $3}' | head -50",
            )
        result["services"] = [s for s in svc_raw.splitlines() if s.strip()]

        port_raw = _ssh_run(
            client,
            "ss -tlnp 2>/dev/null | awk 'NR>1 && /LISTEN/{print}' | head -30",
        )
        result["listening_ports"] = [p for p in port_raw.splitlines() if p.strip()]

        cpu_cores_raw = _ssh_run(client, "nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null")
        cpu_model_raw = _ssh_run(
            client,
            "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || sysctl -n machdep.cpu.brand_string 2>/dev/null",
        )
        mem_raw = _ssh_run(
            client,
            "free -m 2>/dev/null | awk '/Mem:/{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1048576)}'",
        )
        disk_raw = _ssh_run(
            client,
            r"df -BG / 2>/dev/null | tail -1 | awk '{gsub(/G/,\"\",$2); print $2}'",
        )
        users_raw = _ssh_run(
            client,
            r"awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd 2>/dev/null | head -20",
        )

        result["hardware"] = {
            "cpu_cores": _safe_int(cpu_cores_raw),
            "cpu_model": cpu_model_raw,
            "ram_mb": _safe_int(mem_raw),
            "disk_gb": _safe_int(disk_raw),
        }
        result["local_users"] = [u for u in users_raw.splitlines() if u.strip()]

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        client.close()

    return result


# ── WinRM ──────────────────────────────────────────────────────────────────────

def _winrm_run(protocol: Any, cmd: str) -> str:
    try:
        rs = protocol.run_ps(cmd)
        return rs.std_out.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _winrm_json(protocol: Any, cmd: str) -> Any:
    raw = _winrm_run(protocol, cmd)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def winrm_deep_scan(
    ip: str,
    port: int = 5985,
    username: str = "",
    password: str = "",
    use_ssl: bool = False,
    timeout: int = 30,
) -> dict:
    if not _WINRM:
        return {"error": "pywinrm not installed"}

    result = _empty_result(ip, "winrm")
    try:
        session = winrm.Session(
            f"{'https' if use_ssl else 'http'}://{ip}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=timeout,
            operation_timeout_sec=timeout,
        )
        protocol = session.protocol
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    try:
        os_data = _winrm_json(
            protocol,
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,Architecture | ConvertTo-Json -Compress",
        )
        result["os_info"] = os_data if isinstance(os_data, dict) else {}

        hostname_raw = _winrm_run(protocol, "$env:COMPUTERNAME")
        result["hostname"] = hostname_raw

        sw_data = _winrm_json(
            protocol,
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "2>$null | Where-Object {$_.DisplayName} | "
            "Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress",
        )
        pkgs: list[dict] = []
        if isinstance(sw_data, list):
            entries = sw_data
        elif isinstance(sw_data, dict):
            entries = [sw_data]
        else:
            entries = []
        seen_keys: set[tuple[str, str]] = set()
        for entry in entries:
            name = (entry.get("DisplayName") or "").strip()
            version = (entry.get("DisplayVersion") or "").strip()
            vendor = (entry.get("Publisher") or "").strip()
            if not name:
                continue
            if _OS_NOISE_RE.match(name):
                continue
            k = (name.lower(), version)
            if k in seen_keys:
                continue
            seen_keys.add(k)
            pkgs.append({"name": name, "version": version, "vendor": vendor, "package_manager": "windows", "architecture": ""})
        result["packages"] = pkgs

        svc_data = _winrm_json(
            protocol,
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name | ConvertTo-Json -Compress",
        )
        if isinstance(svc_data, list):
            result["services"] = [s.get("Name", "") for s in svc_data if s.get("Name")]
        elif isinstance(svc_data, dict):
            result["services"] = [svc_data.get("Name", "")] if svc_data.get("Name") else []

        cpu_data = _winrm_json(
            protocol,
            "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores | ConvertTo-Json -Compress",
        )
        cpu_model = ""
        cpu_cores = 0
        if isinstance(cpu_data, list) and cpu_data:
            cpu_model = cpu_data[0].get("Name", "")
            cpu_cores = sum(int(c.get("NumberOfCores", 0) or 0) for c in cpu_data)
        elif isinstance(cpu_data, dict):
            cpu_model = cpu_data.get("Name", "")
            cpu_cores = int(cpu_data.get("NumberOfCores", 0) or 0)

        mem_raw = _winrm_run(
            protocol,
            "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1MB)",
        )
        mem_mb = _safe_int(mem_raw)

        disk_data = _winrm_json(
            protocol,
            "Get-PSDrive C | Select-Object @{n='Used';e={[math]::Round($_.Used/1GB)}},@{n='Free';e={[math]::Round($_.Free/1GB)}} | ConvertTo-Json -Compress",
        )
        disk_gb = 0
        if isinstance(disk_data, dict):
            disk_gb = int(disk_data.get("Used", 0) or 0) + int(disk_data.get("Free", 0) or 0)

        result["hardware"] = {
            "cpu_cores": cpu_cores,
            "cpu_model": cpu_model,
            "ram_mb": mem_mb,
            "disk_gb": disk_gb,
        }

        users_data = _winrm_json(
            protocol,
            "Get-LocalUser | Where-Object {$_.Enabled} | Select-Object Name | ConvertTo-Json -Compress",
        )
        if isinstance(users_data, list):
            result["local_users"] = [u.get("Name", "") for u in users_data if u.get("Name")]
        elif isinstance(users_data, dict):
            result["local_users"] = [users_data.get("Name", "")] if users_data.get("Name") else []

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


# ── Auto-detect ────────────────────────────────────────────────────────────────

def detect_and_scan(ip: str, credentials: dict, timeout: int = 15) -> dict:
    ssh_kwargs: dict[str, Any] = {
        "ip": ip,
        "port": credentials.get("ssh_port", 22),
        "username": credentials.get("username", ""),
        "password": credentials.get("password", ""),
        "key_path": credentials.get("key_path", ""),
        "timeout": timeout,
    }
    result = ssh_deep_scan(**ssh_kwargs)
    if result.get("status") == "ok":
        return result

    log.debug("SSH failed for %s (%s), trying WinRM", ip, result.get("error", ""))
    winrm_kwargs: dict[str, Any] = {
        "ip": ip,
        "port": credentials.get("winrm_port", 5985),
        "username": credentials.get("username", ""),
        "password": credentials.get("password", ""),
        "use_ssl": credentials.get("use_ssl", False),
        "timeout": timeout,
    }
    return winrm_deep_scan(**winrm_kwargs)
