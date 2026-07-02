/**
 * pages/edr/EdrPoliciesPage.jsx — CyEDR Policy Management Console
 *
 * Full policy management: create, edit, and assign endpoint policies across
 * all 7 policy types mirroring enterprise EDR vendors:
 *
 *   threat_prevention   — real-time AI, quarantine, CyScan, ransomware rollback
 *   device_control      — USB, WiFi, Bluetooth, camera, microphone, clipboard
 *   app_control         — whitelist/blacklist/audit, hash/publisher/path rules
 *   network_control     — host firewall, DNS sinkhole, connection logging
 *   exclusions          — scan exclusions (paths, processes, hashes, extensions)
 *   update_policy       — auto-update, maintenance windows, channels
 *   isolation_exceptions — IPs/ports reachable during network isolation
 */
import React, { useEffect, useState, useCallback, useRef } from "react";
import { CyScanRulesContent } from "./EdrCyScanRulesPage";

const BG      = "#0a0e1a";
const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const POLICY_TYPE_CFG = {
  threat_prevention:   { label:"Threat Prevention",    color:"#ff3b3b", icon:"🛡️",  desc:"Real-time protection, behavioral AI, CyScan, ransomware rollback" },
  device_control:      { label:"Device Control",       color:"#ff8c00", icon:"🔌",  desc:"USB, WiFi, Bluetooth, camera, microphone, removable media" },
  app_control:         { label:"App Control",          color:"#b06eff", icon:"📦",  desc:"Application whitelist/blacklist, publisher and hash rules" },
  network_control:     { label:"Network Control",      color:"#4d9eff", icon:"🌐",  desc:"Host firewall, inbound/outbound defaults, DNS sinkhole" },
  exclusions:          { label:"Exclusions",           color:"#f5c518", icon:"🔕",  desc:"Scan exclusions by path, process, file extension, hash" },
  update_policy:       { label:"Update Policy",        color:"#00e5a0", icon:"🔄",  desc:"Auto-update, channel (stable/beta/LTS), maintenance windows" },
  isolation_exceptions:{ label:"Isolation Exceptions", color:"#888",    icon:"🔓",  desc:"IPs and ports reachable when an endpoint is isolated" },
  network_probe:       { label:"Network Probe",        color:"#00d4ff", icon:"📡",  desc:"Designate this agent as a local network scanner — enables IoT, SNMP, and deep scan behind NAT/firewall" },
};

const AI_SENSITIVITY_LABELS = {
  low:         "Low — fewer alerts, higher threshold",
  medium:      "Balanced (recommended)",
  high:        "High — catch more, some false positives",
  aggressive:  "Aggressive — maximum detection coverage",
};

// ── Shared UI primitives ──────────────────────────────────────────────────────
function Toggle({ value, onChange, label, sublabel, disabled }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0", borderBottom:BORDER }}>
      <div>
        <div style={{ fontSize:13, color: disabled ? "#555" : "#e8eaf0" }}>{label}</div>
        {sublabel && <div style={{ fontSize:11, color:"#555", marginTop:2 }}>{sublabel}</div>}
      </div>
      <div
        onClick={() => !disabled && onChange(!value)}
        style={{
          width:42, height:24, borderRadius:12, cursor: disabled ? "default" : "pointer",
          background: value && !disabled ? ACCENT : "#2a2a3a",
          position:"relative", transition:"background 0.2s", flexShrink:0,
        }}
      >
        <div style={{
          position:"absolute", top:3, left: value ? 21 : 3,
          width:18, height:18, borderRadius:"50%", background:"white",
          transition:"left 0.2s",
        }}/>
      </div>
    </div>
  );
}

function Select({ value, onChange, options, label }) {
  return (
    <div style={{ marginBottom:14 }}>
      {label && <div style={{ fontSize:11, color:"#555", marginBottom:5 }}>{label}</div>}
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6,
          color:"#e8eaf0", padding:"7px 12px", fontSize:12, width:"100%", cursor:"pointer",
        }}
      >
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

function TagList({ values, onAdd, onRemove, placeholder, label }) {
  const [input, setInput] = useState("");
  const add = () => {
    const v = input.trim();
    if (v && !values.includes(v)) { onAdd(v); setInput(""); }
  };
  return (
    <div style={{ marginBottom:14 }}>
      {label && <div style={{ fontSize:11, color:"#555", marginBottom:6 }}>{label}</div>}
      <div style={{ display:"flex", gap:8, marginBottom:8 }}>
        <input
          value={input} onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&add()}
          placeholder={placeholder}
          style={{
            flex:1, background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6,
            color:"#e8eaf0", padding:"6px 12px", fontSize:12, outline:"none",
          }}
        />
        <button onClick={add} style={{
          border:`1px solid ${ACCENT}44`, borderRadius:6, background:"transparent",
          color:ACCENT, padding:"6px 14px", fontSize:12, cursor:"pointer",
        }}>Add</button>
      </div>
      {values.length > 0 && (
        <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
          {values.map(v => (
            <span key={v} style={{
              border:"1px solid rgba(255,255,255,0.15)", borderRadius:4, padding:"2px 10px",
              fontSize:11, color:"#9aa0b0", display:"flex", alignItems:"center", gap:6,
            }}>
              {v}
              <span onClick={()=>onRemove(v)} style={{ cursor:"pointer", color:"#ff5555", fontSize:13 }}>×</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Policy editors per type ───────────────────────────────────────────────────

function ThreatPreventionEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  return (
    <div>
      <div style={{ fontSize:12, color:"#555", marginBottom:14, fontWeight:600, letterSpacing:1 }}>PROTECTION</div>
      <Toggle value={config.realtime_protection} onChange={v=>s("realtime_protection",v)} label="Real-Time Protection" sublabel="Continuously monitor process, file, and memory activity"/>
      <Toggle value={config.behavioral_ai} onChange={v=>s("behavioral_ai",v)} label="Behavioral AI Engine" sublabel="Machine learning model for unknown threat detection"/>
      <Toggle value={config.memory_protection} onChange={v=>s("memory_protection",v)} label="Memory Protection" sublabel="Detect process injection, hollowing, shellcode"/>
      <Toggle value={config.exploit_prevention} onChange={v=>s("exploit_prevention",v)} label="Exploit Prevention" sublabel="Block heap spray, ROP chains, stack pivots"/>
      <Toggle value={config.lsass_protection} onChange={v=>s("lsass_protection",v)} label="LSASS Protection" sublabel="Block unauthorized reads of LSASS memory"/>
      <Toggle value={config.amsi_integration} onChange={v=>s("amsi_integration",v)} label="AMSI Integration (Windows)" sublabel="Hook into Windows Antimalware Scan Interface"/>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>DETECTION</div>
      <Select value={config.ai_sensitivity} onChange={v=>s("ai_sensitivity",v)} label="AI Detection Sensitivity"
        options={Object.entries(AI_SENSITIVITY_LABELS).map(([k,l])=>({value:k,label:l}))} />
      <Toggle value={config.scan_on_write} onChange={v=>s("scan_on_write",v)} label="Scan on File Write"/>
      <Toggle value={config.scan_on_execute} onChange={v=>s("scan_on_execute",v)} label="Scan on Execute"/>
      <Toggle value={config.pua_detection} onChange={v=>s("pua_detection",v)} label="Detect Potentially Unwanted Applications (PUA)"/>
      <Toggle value={config.yara_enabled} onChange={v=>s("yara_enabled",v)} label="CyScan Rule Scanning" sublabel="Custom CyScan rules applied on file events"/>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>RESPONSE</div>
      <Toggle value={config.auto_quarantine} onChange={v=>s("auto_quarantine",v)} label="Auto-Quarantine" sublabel="Automatically quarantine detected malicious files"/>
      <Toggle value={config.auto_remediate} onChange={v=>s("auto_remediate",v)} label="Auto-Remediate" sublabel="Automatically roll back malicious changes (destructive — review carefully)"/>
      <Toggle value={config.ransomware_rollback} onChange={v=>s("ransomware_rollback",v)} label="Ransomware Rollback" sublabel="Restore files from shadow copy on ransomware detection"/>
      <Select value={config.script_control} onChange={v=>s("script_control",v)} label="Script Control"
        options={[{value:"off",label:"Off"},{value:"audit",label:"Audit — log only"},{value:"block",label:"Block — prevent execution"}]} />
      <Select value={config.deep_scan_schedule} onChange={v=>s("deep_scan_schedule",v)} label="Deep Scan Schedule"
        options={[{value:"off",label:"Off"},{value:"daily",label:"Daily"},{value:"weekly",label:"Weekly"},{value:"monthly",label:"Monthly"}]} />
    </div>
  );
}

function DeviceControlEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  const policyOpts = [
    {value:"allow",label:"Allow"},
    {value:"read_only",label:"Read Only"},
    {value:"block",label:"Block"},
    {value:"prompt",label:"Prompt User"},
  ];
  return (
    <div>
      <div style={{ fontSize:12, color:"#555", marginBottom:14, fontWeight:600, letterSpacing:1 }}>REMOVABLE STORAGE</div>
      <Select value={config.usb_policy} onChange={v=>s("usb_policy",v)} label="USB Storage Devices" options={policyOpts}/>
      <Toggle value={config.usb_encrypted_only} onChange={v=>s("usb_encrypted_only",v)} label="Allow Encrypted USB Only" sublabel="Requires BitLocker To Go or VeraCrypt"/>
      <Toggle value={config.usb_corporate_only} onChange={v=>s("usb_corporate_only",v)} label="Corporate-Approved Devices Only" sublabel="Restrict to pre-approved USB device IDs"/>
      <TagList values={config.usb_approved_ids||[]} placeholder="USB device ID (e.g. 0781:5567)"
        label="Approved USB Device IDs" onAdd={v=>s("usb_approved_ids",[...(config.usb_approved_ids||[]),v])}
        onRemove={v=>s("usb_approved_ids",(config.usb_approved_ids||[]).filter(x=>x!==v))} />
      <Select value={config.removable_media} onChange={v=>s("removable_media",v)} label="SD Cards / Removable Media" options={policyOpts}/>
      <Select value={config.cdrom_policy} onChange={v=>s("cdrom_policy",v)} label="CD-ROM / DVD Drives" options={[{value:"allow",label:"Allow"},{value:"block",label:"Block"}]}/>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>WIRELESS</div>
      <Select value={config.wifi_policy} onChange={v=>s("wifi_policy",v)} label="Wi-Fi"
        options={[{value:"allow",label:"Allow All"},{value:"managed",label:"Managed — approved SSIDs only"},{value:"block",label:"Block All"}]}/>
      <TagList values={config.wifi_approved_ssids||[]} placeholder="SSID name"
        label="Approved Wi-Fi Networks (if Managed)" onAdd={v=>s("wifi_approved_ssids",[...(config.wifi_approved_ssids||[]),v])}
        onRemove={v=>s("wifi_approved_ssids",(config.wifi_approved_ssids||[]).filter(x=>x!==v))} />
      <Toggle value={config.wifi_personal_hotspot==="block"} onChange={v=>s("wifi_personal_hotspot",v?"block":"allow")} label="Block Personal Hotspot"/>
      <Select value={config.bluetooth_policy} onChange={v=>s("bluetooth_policy",v)} label="Bluetooth"
        options={[{value:"allow",label:"Allow"},{value:"managed",label:"Managed"},{value:"block",label:"Block"}]}/>
      <Select value={config.bluetooth_file_transfer} onChange={v=>s("bluetooth_file_transfer",v)} label="Bluetooth File Transfer"
        options={[{value:"allow",label:"Allow"},{value:"block",label:"Block"}]}/>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>PERIPHERALS</div>
      <Select value={config.camera_policy} onChange={v=>s("camera_policy",v)} label="Camera" options={[{value:"allow",label:"Allow"},{value:"block",label:"Block"}]}/>
      <Select value={config.microphone_policy} onChange={v=>s("microphone_policy",v)} label="Microphone" options={[{value:"allow",label:"Allow"},{value:"block",label:"Block"}]}/>
      <Select value={config.printer_network} onChange={v=>s("printer_network",v)} label="Network Printers" options={[{value:"allow",label:"Allow"},{value:"block",label:"Block"}]}/>
      <Select value={config.clipboard_policy} onChange={v=>s("clipboard_policy",v)} label="Clipboard Sharing"
        options={[{value:"allow",label:"Allow"},{value:"monitor",label:"Monitor"},{value:"block",label:"Block"}]}/>
      <Select value={config.screenshot_policy} onChange={v=>s("screenshot_policy",v)} label="Screen Capture"
        options={[{value:"allow",label:"Allow"},{value:"monitor",label:"Monitor (log events)"},{value:"block",label:"Block"}]}/>
    </div>
  );
}

function AppControlEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  return (
    <div>
      <Select value={config.mode} onChange={v=>s("mode",v)} label="App Control Mode"
        options={[
          {value:"off",      label:"Off — no app restrictions"},
          {value:"audit",    label:"Audit — log only, no blocking"},
          {value:"blacklist",label:"Blacklist — block specified apps"},
          {value:"whitelist",label:"Whitelist — allow only approved apps (strict)"},
        ]}/>
      <Toggle value={config.block_unsigned} onChange={v=>s("block_unsigned",v)} label="Block Unsigned Executables"/>
      <Toggle value={config.block_unknown} onChange={v=>s("block_unknown",v)} label="Block Unknown Publishers"/>
      <Toggle value={config.allow_trusted_publishers} onChange={v=>s("allow_trusted_publishers",v)} label="Always Allow Trusted System Publishers" sublabel="Microsoft, Apple, major OS vendors"/>
      <Toggle value={config.script_engines_block} onChange={v=>s("script_engines_block",v)} label="Block Script Engines in Whitelist Mode" sublabel="Restrict PowerShell, WScript, cmd in strict whitelist"/>

      <TagList values={config.allowed_apps||[]} placeholder="App name or path (e.g. chrome.exe)" label="Allowed Applications"
        onAdd={v=>s("allowed_apps",[...(config.allowed_apps||[]),v])} onRemove={v=>s("allowed_apps",(config.allowed_apps||[]).filter(x=>x!==v))}/>
      <TagList values={config.blocked_apps||[]} placeholder="App name or path (e.g. torrent.exe)" label="Blocked Applications"
        onAdd={v=>s("blocked_apps",[...(config.blocked_apps||[]),v])} onRemove={v=>s("blocked_apps",(config.blocked_apps||[]).filter(x=>x!==v))}/>
    </div>
  );
}

function NetworkControlEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  return (
    <div>
      <Toggle value={config.host_firewall_enabled} onChange={v=>s("host_firewall_enabled",v)} label="Host Firewall" sublabel="CyEDR managed endpoint firewall"/>
      <Select value={config.default_inbound} onChange={v=>s("default_inbound",v)} label="Default Inbound Traffic"
        options={[{value:"allow",label:"Allow"},{value:"block",label:"Block (recommended)"}]}/>
      <Select value={config.default_outbound} onChange={v=>s("default_outbound",v)} label="Default Outbound Traffic"
        options={[{value:"allow",label:"Allow (recommended)"},{value:"block",label:"Block"}]}/>
      <Select value={config.connection_logging} onChange={v=>s("connection_logging",v)} label="Connection Logging"
        options={[{value:"off",label:"Off"},{value:"anomalies",label:"Anomalies only"},{value:"all",label:"All connections (verbose)"}]}/>
      <Toggle value={config.block_malicious_dns} onChange={v=>s("block_malicious_dns",v)} label="Block Malicious DNS" sublabel="Sinkhole known C2 domains from threat intelligence"/>
      <Toggle value={config.dns_sinkhole} onChange={v=>s("dns_sinkhole",v)} label="Custom DNS Sinkhole" sublabel="Add custom domains below"/>
      <TagList values={config.dns_sinkhole_domains||[]} placeholder="malicious.example.com" label="Custom Sinkhole Domains"
        onAdd={v=>s("dns_sinkhole_domains",[...(config.dns_sinkhole_domains||[]),v])} onRemove={v=>s("dns_sinkhole_domains",(config.dns_sinkhole_domains||[]).filter(x=>x!==v))}/>
      <Toggle value={config.bandwidth_monitor} onChange={v=>s("bandwidth_monitor",v)} label="Bandwidth Monitoring"/>
      <Toggle value={config.proxy_enforcement} onChange={v=>s("proxy_enforcement",v)} label="Proxy Enforcement" sublabel="Force outbound traffic through corporate proxy"/>
    </div>
  );
}

function ExclusionsEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  return (
    <div>
      <TagList values={config.paths||[]} placeholder="/var/log or C:\\ProgramData\\app" label="Excluded Paths"
        onAdd={v=>s("paths",[...(config.paths||[]),v])} onRemove={v=>s("paths",(config.paths||[]).filter(x=>x!==v))}/>
      <TagList values={config.processes||[]} placeholder="myapp.exe or /usr/bin/java" label="Excluded Processes"
        onAdd={v=>s("processes",[...(config.processes||[]),v])} onRemove={v=>s("processes",(config.processes||[]).filter(x=>x!==v))}/>
      <TagList values={config.extensions||[]} placeholder=".log or .bak" label="Excluded File Extensions"
        onAdd={v=>s("extensions",[...(config.extensions||[]),v])} onRemove={v=>s("extensions",(config.extensions||[]).filter(x=>x!==v))}/>
      <TagList values={config.hashes||[]} placeholder="SHA-256 hash" label="Excluded File Hashes"
        onAdd={v=>s("hashes",[...(config.hashes||[]),v])} onRemove={v=>s("hashes",(config.hashes||[]).filter(x=>x!==v))}/>
      <TagList values={config.network_ips||[]} placeholder="10.0.0.0/8 or 192.168.1.100" label="Excluded Network IPs/Ranges"
        onAdd={v=>s("network_ips",[...(config.network_ips||[]),v])} onRemove={v=>s("network_ips",(config.network_ips||[]).filter(x=>x!==v))}/>
    </div>
  );
}

function UpdatePolicyEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  const DAYS = ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"];
  return (
    <div>
      <Toggle value={config.auto_update} onChange={v=>s("auto_update",v)} label="Automatic Updates" sublabel="Agent and detection content auto-update"/>
      <Select value={config.channel} onChange={v=>s("channel",v)} label="Update Channel"
        options={[{value:"stable",label:"Stable (recommended)"},{value:"beta",label:"Beta"},{value:"lts",label:"LTS — Long Term Support"}]}/>
      <Select value={config.reboot_required} onChange={v=>s("reboot_required",v)} label="Post-Update Reboot"
        options={[{value:"auto",label:"Auto-reboot"},{value:"prompt",label:"Prompt user"},{value:"defer",label:"Defer — wait for next planned window"}]}/>
      <div style={{ marginBottom:14 }}>
        <div style={{ fontSize:11, color:"#555", marginBottom:6 }}>Maintenance Window</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
          <div>
            <div style={{ fontSize:10, color:"#444", marginBottom:4 }}>Start Time</div>
            <input type="time" value={config.maintenance_window_start||"02:00"} onChange={e=>s("maintenance_window_start",e.target.value)}
              style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"6px 10px", fontSize:12, width:"100%" }}/>
          </div>
          <div>
            <div style={{ fontSize:10, color:"#444", marginBottom:4 }}>End Time</div>
            <input type="time" value={config.maintenance_window_end||"04:00"} onChange={e=>s("maintenance_window_end",e.target.value)}
              style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"6px 10px", fontSize:12, width:"100%" }}/>
          </div>
        </div>
        <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginTop:8 }}>
          {DAYS.map(d => (
            <span key={d}
              onClick={() => {
                const curr = config.maintenance_days||[];
                s("maintenance_days", curr.includes(d) ? curr.filter(x=>x!==d) : [...curr,d]);
              }}
              style={{
                fontSize:11, padding:"3px 10px", borderRadius:4, cursor:"pointer",
                border:`1px solid ${(config.maintenance_days||[]).includes(d) ? ACCENT : "#333"}`,
                color:(config.maintenance_days||[]).includes(d) ? ACCENT : "#555",
                background:(config.maintenance_days||[]).includes(d) ? `${ACCENT}22` : "transparent",
              }}>{d.slice(0,3).toUpperCase()}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function IsolationExceptionsEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  return (
    <div>
      <div style={{ background:"rgba(255,140,0,0.08)", border:"1px solid rgba(255,140,0,0.2)", borderRadius:8, padding:"10px 14px", marginBottom:16, fontSize:12, color:"#ff8c00" }}>
        These settings define what remains accessible on an endpoint when it is fully isolated.
        The CyEDR management connection is always preserved regardless of these settings.
      </div>
      <TagList values={config.allowed_ips||[]} placeholder="10.0.0.5 or 192.168.1.0/24" label="Allowed IPs During Isolation"
        onAdd={v=>s("allowed_ips",[...(config.allowed_ips||[]),v])} onRemove={v=>s("allowed_ips",(config.allowed_ips||[]).filter(x=>x!==v))}/>
      <TagList values={(config.allowed_ports||[]).map(String)} placeholder="443 or 8443" label="Allowed Ports During Isolation"
        onAdd={v=>s("allowed_ports",[...(config.allowed_ports||[]),parseInt(v)||0].filter(Boolean))}
        onRemove={v=>s("allowed_ports",(config.allowed_ports||[]).filter(x=>String(x)!==v))}/>
      <Toggle value={config.allow_dns} onChange={v=>s("allow_dns",v)} label="Allow DNS Resolution" sublabel="Keep DNS queries active during isolation"/>
      <Toggle value={config.allow_dhcp} onChange={v=>s("allow_dhcp",v)} label="Allow DHCP" sublabel="Keep DHCP renewal active during isolation"/>
    </div>
  );
}

function NetworkProbeEditor({ config, onChange }) {
  const s = (k, v) => onChange({ ...config, [k]: v });
  const scanTypes = config.scan_types || ["subnet"];
  const toggleScanType = (t) => {
    const next = scanTypes.includes(t) ? scanTypes.filter(x => x !== t) : [...scanTypes, t];
    s("scan_types", next.length ? next : ["subnet"]);
  };

  return (
    <div>
      <div style={{ background:"rgba(0,212,255,0.06)", border:"1px solid rgba(0,212,255,0.2)", borderRadius:8, padding:"10px 14px", marginBottom:16, fontSize:12, color:"#00d4ff" }}>
        Deploy this policy to <strong>one agent per network segment</strong> that sits inside the customer's LAN.
        That agent runs nmap/SNMP locally and reports results to Cy360 — no inbound firewall rules needed.
        <br/>All other agents are unaffected; zero extra load on them.
      </div>

      <div style={{ fontSize:12, color:"#555", marginBottom:14, fontWeight:600, letterSpacing:1 }}>PROBE SETTINGS</div>
      <Toggle
        value={config.enabled}
        onChange={v => s("enabled", v)}
        label="Enable Network Probe"
        sublabel="Start local nmap/SNMP scanning on this agent"
      />
      <div style={{ marginBottom:14 }}>
        <div style={{ fontSize:11, color:"#555", marginBottom:5 }}>Subnet to Scan (CIDR)</div>
        <input
          value={config.subnet || ""}
          onChange={e => s("subnet", e.target.value)}
          placeholder="192.168.1.0/24 — leave blank to auto-detect from agent IP"
          style={{
            width:"100%", background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6,
            color:"#e8eaf0", padding:"7px 12px", fontSize:12, boxSizing:"border-box",
          }}
        />
      </div>
      <div style={{ marginBottom:14 }}>
        <div style={{ fontSize:11, color:"#555", marginBottom:5 }}>Auto-Scan Interval (minutes) — 0 = on-demand only</div>
        <input
          type="number" min="0" max="10080"
          value={config.scan_interval_minutes ?? 60}
          onChange={e => s("scan_interval_minutes", parseInt(e.target.value) || 0)}
          style={{
            width:120, background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6,
            color:"#e8eaf0", padding:"7px 12px", fontSize:12,
          }}
        />
      </div>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>SCAN TYPES</div>
      {[
        { key:"subnet", label:"Subnet Discovery (nmap)", note:"Ping sweep + port scan to discover all active hosts" },
        { key:"snmp",   label:"SNMP Polling", note:"Read sysDescr, interfaces, uptime from network devices (future)" },
      ].map(({ key, label, note }) => (
        <div key={key} onClick={() => key !== "snmp" && toggleScanType(key)} style={{
          display:"flex", alignItems:"center", gap:12, padding:"10px 0",
          borderBottom:BORDER, cursor: key === "snmp" ? "default" : "pointer",
          opacity: key === "snmp" ? 0.4 : 1,
        }}>
          <div style={{
            width:18, height:18, borderRadius:4, flexShrink:0,
            background: scanTypes.includes(key) ? "#00d4ff" : "transparent",
            border:`1.5px solid ${scanTypes.includes(key) ? "#00d4ff" : "#444"}`,
            display:"flex", alignItems:"center", justifyContent:"center",
          }}>
            {scanTypes.includes(key) && <span style={{ color:"#000", fontSize:11, fontWeight:700 }}>✓</span>}
          </div>
          <div>
            <div style={{ fontSize:13, color:"#e8eaf0" }}>{label}</div>
            <div style={{ fontSize:11, color:"#555", marginTop:2 }}>{note}</div>
          </div>
        </div>
      ))}

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>PORT CONFIGURATION</div>
      <div style={{ marginBottom:14 }}>
        <div style={{ fontSize:11, color:"#555", marginBottom:5 }}>IoT / Service Ports (comma-separated)</div>
        <input
          value={config.ports || ""}
          onChange={e => s("ports", e.target.value)}
          placeholder="22,23,80,443,554,631,8080,8883,9100,161,502,47808"
          style={{
            width:"100%", background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6,
            color:"#e8eaf0", padding:"7px 12px", fontSize:12, boxSizing:"border-box",
          }}
        />
      </div>

      <div style={{ fontSize:12, color:"#555", marginTop:20, marginBottom:14, fontWeight:600, letterSpacing:1 }}>SHADOW AI DNS MONITOR</div>
      <Toggle
        value={config.dns_monitor}
        onChange={v => s("dns_monitor", v)}
        label="Local DNS Monitor"
        sublabel="Run a local DNS forwarder to catch AI SaaS queries from IoT and unmanaged devices"
      />

      <div style={{ marginTop:20, padding:"10px 14px", background:"rgba(255,255,255,0.03)", borderRadius:8, fontSize:11, color:"#555", lineHeight:1.6 }}>
        <strong style={{ color:"#888" }}>Deployment note:</strong> Deploy this policy to exactly one agent per network zone.
        Assigning to multiple agents in the same /24 causes duplicate scan results.
        The agent needs <code style={{ color:"#00d4ff" }}>nmap</code> installed — included in the CyEDR install script for Linux/macOS.
      </div>
    </div>
  );
}

const EDITORS = {
  threat_prevention:    ThreatPreventionEditor,
  device_control:       DeviceControlEditor,
  app_control:          AppControlEditor,
  network_control:      NetworkControlEditor,
  exclusions:           ExclusionsEditor,
  update_policy:        UpdatePolicyEditor,
  isolation_exceptions: IsolationExceptionsEditor,
  network_probe:        NetworkProbeEditor,
};

// ── Assign modal ──────────────────────────────────────────────────────────────
function AssignModal({ policy, agents, groups, onClose, onAssigned }) {
  const [targetType, setTargetType] = useState("agent");
  const [selected,   setSelected]   = useState([]);
  const [busy,       setBusy]       = useState(false);
  const [err,        setErr]        = useState("");

  const items = targetType === "agent" ? agents : groups;
  const idKey = targetType === "agent" ? "agent_id" : "id";
  const nameKey = targetType === "agent" ? "hostname" : "name";

  const toggle = (id) => setSelected(s => s.includes(id) ? s.filter(x=>x!==id) : [...s, id]);

  const submit = async () => {
    if (!selected.length) { setErr("Select at least one target"); return; }
    setBusy(true); setErr("");
    try {
      const res = await fetch(`/api/edr/policies/${policy.id}/assign`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ target_type: targetType, target_ids: selected }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      onAssigned();
      onClose();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:9999 }}>
      <div style={{ background:"#12182b", border:BORDER, borderRadius:12, padding:24, maxWidth:500, width:"90%", maxHeight:"80vh", display:"flex", flexDirection:"column" }}>
        <div style={{ fontSize:15, fontWeight:700, color:"#e8eaf0", marginBottom:4 }}>Assign Policy</div>
        <div style={{ fontSize:12, color:"#555", marginBottom:16 }}>{policy.name} → {policy.policy_type}</div>
        <div style={{ display:"flex", gap:8, marginBottom:14 }}>
          {["agent","group"].map(t => (
            <button key={t} onClick={()=>{setTargetType(t);setSelected([]);}} style={{
              border:`1px solid ${targetType===t?ACCENT:"#333"}`, borderRadius:6,
              background:targetType===t?`${ACCENT}22`:"transparent",
              color:targetType===t?ACCENT:"#666", padding:"5px 14px", fontSize:12, cursor:"pointer",
            }}>{t==="agent"?"Individual Agents":"Groups"}</button>
          ))}
        </div>
        <div style={{ flex:1, overflowY:"auto", display:"flex", flexDirection:"column", gap:6 }}>
          {items.map(item => (
            <div key={item[idKey]} onClick={()=>toggle(item[idKey])} style={{
              display:"flex", alignItems:"center", gap:10, padding:"8px 12px",
              background:selected.includes(item[idKey])?`${ACCENT}11`:CARD_BG,
              border:`1px solid ${selected.includes(item[idKey])?ACCENT+"44":"rgba(255,255,255,0.07)"}`,
              borderRadius:7, cursor:"pointer",
            }}>
              <div style={{
                width:16, height:16, borderRadius:3, flexShrink:0,
                border:`2px solid ${selected.includes(item[idKey])?ACCENT:"#444"}`,
                background:selected.includes(item[idKey])?ACCENT:"transparent",
              }}/>
              <div>
                <div style={{ fontSize:12, color:"#e8eaf0" }}>{item[nameKey]}</div>
                {targetType==="agent" && <div style={{ fontSize:10, color:"#555" }}>{item.os_type} · {item.asset_type}</div>}
                {targetType==="group" && <div style={{ fontSize:10, color:"#555" }}>{item.member_count||0} agents</div>}
              </div>
            </div>
          ))}
          {items.length === 0 && <div style={{ color:"#555", fontSize:12, padding:12 }}>No {targetType}s found.</div>}
        </div>
        {err && <div style={{ color:"#ff7070", fontSize:12, marginTop:10 }}>{err}</div>}
        <div style={{ display:"flex", gap:10, justifyContent:"flex-end", marginTop:16 }}>
          <button onClick={onClose} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"6px 16px", cursor:"pointer" }}>Cancel</button>
          <button onClick={submit} disabled={busy} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"6px 18px", cursor:"pointer", opacity:busy?0.6:1 }}>{busy?"Assigning…":"Assign"}</button>
        </div>
      </div>
    </div>
  );
}

// ── Groups Tab ────────────────────────────────────────────────────────────────
function GroupsTab({ agents }) {
  const [groups,     setGroups]     = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [newName,    setNewName]    = useState("");
  const [creating,   setCreating]   = useState(false);
  const [addingTo,   setAddingTo]   = useState(null);
  const [selected,   setSelected]   = useState([]);
  const [err,        setErr]        = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const r = await fetch("/api/edr/groups").catch(() => null);
    if (r?.ok) setGroups((await r.json()).groups || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const createGroup = async () => {
    if (!newName.trim()) return;
    setErr("");
    const r = await fetch("/api/edr/groups", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ name:newName }) });
    if (r.ok) { setNewName(""); setCreating(false); load(); }
    else setErr("Failed to create group");
  };

  const deleteGrp = async (id, name) => {
    if (!confirm(`Delete group "${name}"?`)) return;
    await fetch(`/api/edr/groups/${id}`, { method:"DELETE" });
    load();
  };

  const addMembers = async () => {
    if (!selected.length) return;
    await fetch(`/api/edr/groups/${addingTo}/members`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ agent_ids:selected }) });
    setAddingTo(null); setSelected([]); load();
  };

  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
        <div style={{ fontSize:12, color:"#9aa0b0" }}>{groups.length} group{groups.length!==1?"s":""}</div>
        <button onClick={()=>setCreating(c=>!c)} style={{ border:"none", borderRadius:7, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"9px 20px", cursor:"pointer", fontSize:13 }}>+ New Group</button>
      </div>

      {creating && (
        <div style={{ background:CARD_BG, border:BORDER, borderRadius:10, padding:"16px 20px", marginBottom:20 }}>
          <div style={{ fontSize:12, color:"#555", marginBottom:8 }}>Group name</div>
          <div style={{ display:"flex", gap:10 }}>
            <input value={newName} onChange={e=>setNewName(e.target.value)} placeholder="e.g. Linux Servers" autoFocus
              style={{ flex:1, background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"7px 12px", fontSize:12, outline:"none" }}/>
            <button onClick={createGroup} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"7px 18px", cursor:"pointer" }}>Create</button>
            <button onClick={()=>setCreating(false)} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"7px 14px", cursor:"pointer" }}>Cancel</button>
          </div>
          {err && <div style={{ color:"#ff7070", fontSize:11, marginTop:8 }}>{err}</div>}
        </div>
      )}

      {/* Add-members modal */}
      {addingTo && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.7)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div style={{ background:"#111827", border:BORDER, borderRadius:12, padding:"24px 28px", width:480, maxHeight:"70vh", display:"flex", flexDirection:"column" }}>
            <div style={{ fontSize:14, fontWeight:700, color:"#e8eaf0", marginBottom:16 }}>Add Agents to Group</div>
            <div style={{ flex:1, overflowY:"auto", marginBottom:16 }}>
              {agents.map(a => (
                <div key={a.agent_id} onClick={()=>setSelected(s=>s.includes(a.agent_id)?s.filter(x=>x!==a.agent_id):[...s,a.agent_id])}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 10px", borderRadius:6, cursor:"pointer", background:selected.includes(a.agent_id)?"rgba(0,229,160,0.08)":"transparent" }}>
                  <input type="checkbox" readOnly checked={selected.includes(a.agent_id)} style={{ accentColor:ACCENT }}/>
                  <div>
                    <div style={{ fontSize:12, color:"#e8eaf0" }}>{a.hostname}</div>
                    <div style={{ fontSize:10, color:"#555" }}>{a.os_type} · {a.ip_address}</div>
                  </div>
                </div>
              ))}
              {agents.length===0 && <div style={{ color:"#555", fontSize:12, padding:12 }}>No active agents.</div>}
            </div>
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button onClick={()=>{setAddingTo(null);setSelected([]);}} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"6px 16px", cursor:"pointer" }}>Cancel</button>
              <button onClick={addMembers} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"6px 18px", cursor:"pointer" }}>Add {selected.length||""} Agent{selected.length!==1?"s":""}</button>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign:"center", color:"#555", padding:40 }}>Loading groups…</div>
      ) : groups.length===0 ? (
        <div style={{ textAlign:"center", color:"#555", padding:60, fontSize:13 }}>No groups yet. Create one to batch-assign policies.</div>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
          {groups.map(g => (
            <div key={g.id} style={{ background:CARD_BG, border:BORDER, borderRadius:10, padding:"14px 20px", display:"flex", alignItems:"center", gap:12 }}>
              <span style={{ fontSize:18 }}>👥</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:14, fontWeight:700, color:"#e8eaf0" }}>{g.name}</div>
                <div style={{ fontSize:11, color:"#555", marginTop:2 }}>{g.member_count||0} agents</div>
              </div>
              <button onClick={()=>{setAddingTo(g.id);setSelected([]);}} style={{ border:`1px solid ${ACCENT}44`, borderRadius:5, background:"transparent", color:ACCENT, padding:"4px 12px", fontSize:11, cursor:"pointer" }}>+ Add Agents</button>
              <button onClick={()=>deleteGrp(g.id,g.name)} style={{ border:"1px solid #ff3b3b44", borderRadius:5, background:"transparent", color:"#ff3b3b", padding:"4px 12px", fontSize:11, cursor:"pointer" }}>Delete</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const PAGE_TABS = [
  { id:"policies", label:"Policies",     icon:"📋" },
  { id:"cyscan",   label:"CyScan Rules", icon:"🧬" },
  { id:"groups",   label:"Groups",       icon:"👥" },
];

// ── Main page ─────────────────────────────────────────────────────────────────
export default function EdrPoliciesPage() {
  const [policies,   setPolicies]  = useState([]);
  const [agents,     setAgents]    = useState([]);
  const [groups,     setGroups]    = useState([]);
  const [defaults,   setDefaults]  = useState({});
  const [loading,    setLoading]   = useState(true);
  const [editing,    setEditing]   = useState(null);   // policy being edited
  const [creating,   setCreating]  = useState(false);
  const [newType,    setNewType]   = useState("threat_prevention");
  const [newName,    setNewName]   = useState("");
  const [newDesc,    setNewDesc]   = useState("");
  const [newConfig,  setNewConfig] = useState({});
  const [assigning,  setAssigning] = useState(null);  // policy to assign
  const [filterType, setFilterType] = useState("");
  const [saving,     setSaving]    = useState(false);
  const [error,      setError]     = useState("");
  const [activeTab,  setActiveTab] = useState("policies");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [polRes, agRes, grpRes, defRes] = await Promise.all([
        fetch("/api/edr/policies"),
        fetch("/api/edr/agents?status=active"),
        fetch("/api/edr/groups"),
        fetch("/api/edr/policy-defaults"),
      ]);
      if (polRes.ok) setPolicies((await polRes.json()).policies || []);
      if (agRes.ok)  setAgents((await agRes.json()).agents || []);
      if (grpRes.ok) setGroups((await grpRes.json()).groups || []);
      if (defRes.ok) setDefaults((await defRes.json()).defaults || {});
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const startCreate = () => {
    setNewConfig(JSON.parse(JSON.stringify(defaults[newType] || {})));
    setCreating(true);
  };

  const handleTypeChange = (t) => {
    setNewType(t);
    setNewConfig(JSON.parse(JSON.stringify(defaults[t] || {})));
  };

  const saveNew = async () => {
    if (!newName.trim()) { setError("Policy name required"); return; }
    setSaving(true); setError("");
    try {
      const res = await fetch("/api/edr/policies", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ name:newName, policy_type:newType, config:newConfig, description:newDesc }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      setCreating(false); setNewName(""); setNewDesc("");
      load();
    } catch (e) { setError(e.message); }
    finally { setSaving(false); }
  };

  const saveEdit = async () => {
    setSaving(true); setError("");
    try {
      const res = await fetch(`/api/edr/policies/${editing.id}`, {
        method:"PUT",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ name:editing.name, description:editing.description, config:editing.config, enabled:editing.enabled }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      setEditing(null); load();
    } catch (e) { setError(e.message); }
    finally { setSaving(false); }
  };

  const deletePolicy = async (pol) => {
    if (!confirm(`Delete policy "${pol.name}"? This cannot be undone.`)) return;
    await fetch(`/api/edr/policies/${pol.id}`, { method:"DELETE" });
    load();
  };

  const filtered = filterType ? policies.filter(p => p.policy_type === filterType) : policies;
  const EditorComponent = editing ? EDITORS[editing.policy_type] : null;
  const NewEditorComponent = creating ? EDITORS[newType] : null;

  return (
    <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG }}>
      {assigning && (
        <AssignModal policy={assigning} agents={agents} groups={groups}
          onClose={()=>setAssigning(null)} onAssigned={load} />
      )}

      <div style={{ marginBottom:20 }}>
        <h1 style={{ margin:0, fontSize:22, fontWeight:800, color:"#e8eaf0" }}>Endpoint Defence</h1>
        <div style={{ fontSize:12, color:"#555", marginTop:4 }}>Manage endpoint policies, threat hunting rules, and agent groups</div>
      </div>

      {/* Tab bar */}
      <div style={{ display:"flex", gap:0, marginBottom:28, borderBottom:"1px solid rgba(255,255,255,0.07)" }}>
        {PAGE_TABS.map(tab => (
          <button key={tab.id} onClick={()=>setActiveTab(tab.id)} style={{
            border:"none", borderBottom:activeTab===tab.id?`2px solid ${ACCENT}`:"2px solid transparent",
            background:"transparent", color:activeTab===tab.id?ACCENT:"#666",
            padding:"10px 20px", fontSize:13, fontWeight:activeTab===tab.id?700:400,
            cursor:"pointer", marginBottom:-1, transition:"color 0.15s",
          }}>{tab.icon} {tab.label}</button>
        ))}
      </div>

      {activeTab==="cyscan" && <CyScanRulesContent />}
      {activeTab==="groups" && <GroupsTab agents={agents} />}
      {activeTab==="policies" && (<>

      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:24 }}>
        <div>
          <div style={{ fontSize:12, color:"#9aa0b0" }}>
            {policies.length} policies across {Object.keys(POLICY_TYPE_CFG).length} categories
          </div>
        </div>
        <button onClick={startCreate} style={{
          border:"none", borderRadius:7, background:ACCENT, color:"#0a0e1a",
          fontWeight:700, padding:"9px 20px", cursor:"pointer", fontSize:13,
        }}>+ New Policy</button>
      </div>

      {error && <div style={{ background:"#ff3b3b22", border:"1px solid #ff3b3b44", borderRadius:8, padding:"10px 14px", color:"#ff7070", fontSize:12, marginBottom:16 }}>{error}</div>}

      {/* ── Policy type filter ── */}
      <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginBottom:20 }}>
        <button onClick={()=>setFilterType("")} style={{
          border:`1px solid ${!filterType?ACCENT:"#333"}`, borderRadius:6,
          background:!filterType?`${ACCENT}22`:"transparent",
          color:!filterType?ACCENT:"#555", padding:"5px 14px", fontSize:11, cursor:"pointer",
        }}>All</button>
        {Object.entries(POLICY_TYPE_CFG).map(([t,cfg]) => (
          <button key={t} onClick={()=>setFilterType(t)} style={{
            border:`1px solid ${filterType===t?cfg.color:"#333"}44`,
            borderRadius:6, background:filterType===t?`${cfg.color}22`:"transparent",
            color:filterType===t?cfg.color:"#666", padding:"5px 14px", fontSize:11, cursor:"pointer",
          }}>{cfg.icon} {cfg.label}</button>
        ))}
      </div>

      {/* ── Create new policy panel ── */}
      {creating && (
        <div style={{ background:CARD_BG, border:BORDER, borderRadius:12, padding:"20px 24px", marginBottom:24 }}>
          <div style={{ fontSize:14, fontWeight:700, color:"#e8eaf0", marginBottom:16 }}>Create Policy</div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:14 }}>
            <div>
              <div style={{ fontSize:11, color:"#555", marginBottom:4 }}>Policy Name</div>
              <input value={newName} onChange={e=>setNewName(e.target.value)} placeholder="e.g. Production Workstations — Strict"
                style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"7px 12px", fontSize:12, width:"100%", boxSizing:"border-box", outline:"none" }}/>
            </div>
            <div>
              <div style={{ fontSize:11, color:"#555", marginBottom:4 }}>Policy Type</div>
              <select value={newType} onChange={e=>handleTypeChange(e.target.value)}
                style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"7px 12px", fontSize:12, width:"100%", cursor:"pointer" }}>
                {Object.entries(POLICY_TYPE_CFG).map(([t,cfg]) => (
                  <option key={t} value={t}>{cfg.icon} {cfg.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div style={{ marginBottom:16 }}>
            <div style={{ fontSize:11, color:"#555", marginBottom:4 }}>Description (optional)</div>
            <input value={newDesc} onChange={e=>setNewDesc(e.target.value)} placeholder="Brief description of this policy's purpose"
              style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"7px 12px", fontSize:12, width:"100%", boxSizing:"border-box", outline:"none" }}/>
          </div>
          <div style={{ borderTop:BORDER, paddingTop:16, marginBottom:16 }}>
            {NewEditorComponent && <NewEditorComponent config={newConfig} onChange={setNewConfig} />}
          </div>
          <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
            <button onClick={()=>setCreating(false)} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"7px 18px", cursor:"pointer" }}>Cancel</button>
            <button onClick={saveNew} disabled={saving} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"7px 20px", cursor:"pointer", opacity:saving?0.6:1 }}>{saving?"Saving…":"Create Policy"}</button>
          </div>
        </div>
      )}

      {/* ── Policy list ── */}
      {loading ? (
        <div style={{ textAlign:"center", color:"#555", padding:40 }}>Loading policies…</div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign:"center", color:"#555", padding:60, fontSize:13 }}>
          No policies yet. Create one above to control endpoint behaviour.
        </div>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
          {filtered.map(pol => {
            const typeCfg = POLICY_TYPE_CFG[pol.policy_type] || {};
            const isEditingThis = editing?.id === pol.id;
            return (
              <div key={pol.id} style={{
                background:CARD_BG, border:BORDER, borderRadius:10,
                borderLeft:`3px solid ${typeCfg.color||"#888"}`,
                overflow:"hidden",
              }}>
                <div style={{ padding:"14px 20px", display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
                  <span style={{ fontSize:18 }}>{typeCfg.icon}</span>
                  <div style={{ flex:1, minWidth:160 }}>
                    <div style={{ fontSize:14, fontWeight:700, color:"#e8eaf0" }}>{pol.name}</div>
                    <div style={{ fontSize:11, color:"#555", marginTop:2 }}>
                      {typeCfg.label} · {pol.description || "No description"}
                    </div>
                  </div>
                  <span style={{
                    fontSize:10, fontWeight:700, padding:"2px 8px", borderRadius:4,
                    color:pol.enabled?"#00e5a0":"#888", background:pol.enabled?"rgba(0,229,160,0.12)":"rgba(136,136,136,0.12)",
                  }}>{pol.enabled?"ENABLED":"DISABLED"}</span>
                  <div style={{ display:"flex", gap:8 }}>
                    <button onClick={()=>setAssigning(pol)} style={{ border:`1px solid ${typeCfg.color}44`, borderRadius:5, background:"transparent", color:typeCfg.color, padding:"4px 12px", fontSize:11, cursor:"pointer" }}>Assign</button>
                    <button onClick={()=>setEditing(isEditingThis?null:{...pol,config:{...pol.config}})} style={{ border:"1px solid #4d9eff44", borderRadius:5, background:"transparent", color:"#4d9eff", padding:"4px 12px", fontSize:11, cursor:"pointer" }}>
                      {isEditingThis?"Cancel":"Edit"}
                    </button>
                    <button onClick={()=>deletePolicy(pol)} style={{ border:"1px solid #ff3b3b44", borderRadius:5, background:"transparent", color:"#ff3b3b", padding:"4px 12px", fontSize:11, cursor:"pointer" }}>Delete</button>
                  </div>
                </div>

                {isEditingThis && EditorComponent && (
                  <div style={{ borderTop:BORDER, padding:"16px 20px" }}>
                    <EditorComponent config={editing.config} onChange={c=>setEditing({...editing,config:c})} />
                    <div style={{ display:"flex", gap:10, justifyContent:"flex-end", marginTop:12, paddingTop:12, borderTop:BORDER }}>
                      <button onClick={()=>setEditing(null)} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"6px 16px", cursor:"pointer" }}>Cancel</button>
                      <button onClick={saveEdit} disabled={saving} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"6px 18px", cursor:"pointer", opacity:saving?0.6:1 }}>{saving?"Saving…":"Save Changes"}</button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      </>)}
    </div>
  );
}
