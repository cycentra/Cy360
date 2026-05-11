#!/usr/bin/env python3
"""
PATCH — LoginPage.jsx branding update
======================================
Changes:
  1. Headline  "Attack Surface Intelligence Platform"
             → "One Platform. Six Modules." + "FROM SIGNALS TO STRENGTH" sub
  2. Tagline <p> → animated module pill strip (7 modules)
  3. Capability grid → seven module cards with SVG icons + accent colours
  4. Footer line → full module list

Run from repo root:
    python3 patch_login_branding.py
"""
import re, sys
from pathlib import Path

TARGET = Path("portal/src/pages/login/LoginPage.jsx")
if not TARGET.exists():
    TARGET = Path("src/pages/login/LoginPage.jsx")
if not TARGET.exists():
    sys.exit("ERROR: cannot find LoginPage.jsx — run from repo root.")

src = TARGET.read_text(encoding="utf-8")
changes = 0

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — Headline
# ══════════════════════════════════════════════════════════════════════════════
OLD_H1 = (
    '          <h1 style={{ color: "white", fontSize: 36, fontWeight: 700, lineHeight: 1.2, marginBottom: 16 }}>\n'
    '            Attack Surface<br/>\n'
    '            <span style={{ color: "#00e5a0" }}>Intelligence</span> Platform\n'
    '          </h1>'
)
NEW_H1 = (
    '          <h1 style={{ color: "white", fontSize: 34, fontWeight: 700, lineHeight: 1.25, marginBottom: 10 }}>\n'
    '            One Platform.{" "}\n'
    '            <span style={{ color: "#00e5a0" }}>Six Modules.</span>\n'
    '          </h1>\n'
    '          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 14,\n'
    '            fontFamily: "\'Space Mono\',monospace", letterSpacing: "2.5px",\n'
    '            marginBottom: 28, fontWeight: 400, textTransform: "uppercase" }}>\n'
    '            From Signals to Strength\n'
    '          </div>'
)

if OLD_H1 in src:
    src = src.replace(OLD_H1, NEW_H1, 1)
    changes += 1
    print("✓ Patch 1/4: headline updated")
else:
    print("✗ Patch 1/4: headline NOT found — inspect file around 'Attack Surface'")

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2+3 — Replace <p> tagline + capability grid
# ══════════════════════════════════════════════════════════════════════════════
OLD_P_PATTERN = re.compile(
    r'<p style=\{\{ color: "rgba\(255,255,255,0\.65\)", fontSize: 16.*?</p>',
    re.DOTALL,
)

NEW_BRANDING_BLOCK = '''\
          {/* ── Module pill strip ──────────────────────────────────────────── */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 26 }}>
            {[
              { label: "CyASM",     color: "#00e5a0" },
              { label: "CySIEM",    color: "#ff3b3b" },
              { label: "UEBA",      color: "#ff8c00" },
              { label: "CySOAR",    color: "#4d9eff" },
              { label: "CyIRIS",    color: "#b06eff" },
              { label: "CyComp",    color: "#4d9eff" },
              { label: "CyMind AI", color: "#00e5a0" },
            ].map(({ label, color }) => (
              <span key={label} style={{
                background: `${color}12`, color,
                border: `1px solid ${color}35`,
                fontSize: 9, fontFamily: "'Space Mono',monospace", fontWeight: 700,
                padding: "4px 10px", borderRadius: 3, letterSpacing: "0.8px",
              }}>
                {label}
              </span>
            ))}
          </div>

          {/* ── Seven-module capability cards ───────────────────────────────── */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 9 }}>
            {[
              {
                key: "asm", name: "Attack Surface", tag: "CyASM", color: "#00e5a0",
                desc: "14-module external recon: DNS, subdomains, SSL, email, cloud & dark web",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 6.36 15.36M5.64 18.36A9 9 0 0 1 12 3"/><circle cx="12" cy="12" r="3"/></svg>),
              },
              {
                key: "siem", name: "Correlation Engine", tag: "CySIEM", color: "#ff3b3b",
                desc: "Wazuh + ML correlation · MITRE ATT&CK · MISP IOC enrichment",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>),
              },
              {
                key: "ueba", name: "UEBA", tag: "Behavioural", color: "#ff8c00",
                desc: "User & entity baselines · anomaly detection · risk scoring",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>),
              },
              {
                key: "soar", name: "SOAR", tag: "CySOAR", color: "#4d9eff",
                desc: "Node-RED automation · playbooks · response orchestration",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>),
              },
              {
                key: "grc", name: "GRC & DFIR", tag: "CyComp · CyIRIS", color: "#b06eff",
                desc: "Risk register · NIS2 / DORA / ISO 27001 · case management",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>),
              },
              {
                key: "cymind", name: "AI Analyst", tag: "CyMind", color: "#00e5a0",
                desc: "On-prem LLM · RAG · live SIEM grounding · zero egress",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><circle cx="9" cy="10" r="1" fill="currentColor"/><circle cx="12" cy="10" r="1" fill="currentColor"/><circle cx="15" cy="10" r="1" fill="currentColor"/></svg>),
              },
            ].map(({ key, name, tag, color, desc, icon }) => (
              <div key={key}
                style={{
                  background: "rgba(255,255,255,0.025)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderLeft: `2px solid ${color}`,
                  borderRadius: 5, padding: "11px 13px",
                  display: "flex", gap: 10, alignItems: "flex-start",
                  transition: "background 0.2s",
                }}
                onMouseEnter={e => e.currentTarget.style.background = `${color}08`}
                onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: 5, flexShrink: 0,
                  background: `${color}14`, border: `1px solid ${color}28`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color, padding: 5,
                }}>
                  {icon}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 3, flexWrap: "wrap" }}>
                    <span style={{ color: "white", fontSize: 11, fontWeight: 600 }}>{name}</span>
                    <span style={{
                      background: `${color}15`, color, border: `1px solid ${color}35`,
                      fontSize: 8, fontFamily: "'Space Mono',monospace", fontWeight: 700,
                      padding: "1px 5px", borderRadius: 2, letterSpacing: "0.5px",
                    }}>{tag}</span>
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 10,
                    lineHeight: 1.45, fontFamily: "system-ui,sans-serif" }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>'''

if OLD_P_PATTERN.search(src):
    src = OLD_P_PATTERN.sub(NEW_BRANDING_BLOCK, src, count=1)
    changes += 2          # counts as patches 2 + 3
    print("✓ Patch 2/4: tagline → module pill strip")
    print("✓ Patch 3/4: capability grid → seven-module cards")
else:
    print("✗ Patch 2+3/4: tagline <p> NOT found")

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 4 — Footer
# ══════════════════════════════════════════════════════════════════════════════
OLD_FOOTER = (
    "Single sign-on gateway \u00b7 All modules share this session<br/>\n"
    "            CySIEM \u00b7 CyIRIS \u00b7 CySOAR \u2014 one login to rule them all"
)
# Also try 10-space indent variant
OLD_FOOTER_10 = (
    "Single sign-on gateway \u00b7 All modules share this session<br/>\n"
    "          CySIEM \u00b7 CyIRIS \u00b7 CySOAR \u2014 one login to rule them all"
)
NEW_FOOTER_BODY = "CyASM \u00b7 CySIEM \u00b7 UEBA \u00b7 CySOAR \u00b7 CyIRIS \u00b7 CyComp \u00b7 CyMind \u2014 one login"

if OLD_FOOTER in src:
    src = src.replace(OLD_FOOTER,
        "Single sign-on gateway \u00b7 All modules share this session<br/>\n"
        f"            {NEW_FOOTER_BODY}", 1)
    changes += 1
    print("✓ Patch 4/4: footer modules list updated (12-space indent)")
elif OLD_FOOTER_10 in src:
    src = src.replace(OLD_FOOTER_10,
        "Single sign-on gateway \u00b7 All modules share this session<br/>\n"
        f"          {NEW_FOOTER_BODY}", 1)
    changes += 1
    print("✓ Patch 4/4: footer modules list updated (10-space indent)")
else:
    # Flexible fallback
    footer_pat = re.compile(
        r"(Single sign-on gateway \u00b7 All modules share this session<br/>)\s*\n"
        r"(\s*)CySIEM \u00b7 CyIRIS \u00b7 CySOAR \u2014 one login to rule them all"
    )
    m = footer_pat.search(src)
    if m:
        src = footer_pat.sub(
            rf"\1\n\2{NEW_FOOTER_BODY}", src, count=1
        )
        changes += 1
        print("✓ Patch 4/4: footer updated (flexible match)")
    else:
        print("✗ Patch 4/4: footer NOT found — update manually")

# ══════════════════════════════════════════════════════════════════════════════
if changes == 0:
    sys.exit("No changes applied — file may already be patched.")

TARGET.write_text(src, encoding="utf-8")
print(f"\n{'='*55}")
print(f"  {changes}/4 patches applied → {TARGET}")
print(f"{'='*55}")
print("\nNext steps:")
print("  python3 -m py_compile portal/src/pages/login/LoginPage.jsx  # JSX won't py_compile but checks syntax")
print("  cd portal && npm run build  # verify no JSX errors")
print("  git add portal/src/pages/login/LoginPage.jsx")
print("  git commit -m 'feat(login): rebrand to One Platform Six Modules + module cards'")
print("  git push")
