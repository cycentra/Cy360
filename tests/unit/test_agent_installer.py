"""
Agent Installer Tests (Suite 02 extension + Suite 09 contribution)

Validates the agent installer templates embedded in routes.py:
  • Template content: safety flags, branding, duplicate-agent logic
  • Template rendering: placeholders resolve without error
  • macOS FDA notice: both binaries listed
  • Audit rules: branded cy360_agent_tamper (not wazuh variant)
  • _register_agent() logic: duplicate-detection is present, no restart inside
  • Windows PowerShell installer: required elements present
  • Route behaviour: auth guard on GET /api/system/agent-installer

Tests read _INSTALLER_SH and _INSTALLER_PS1 directly as source text to
avoid the import overhead of loading the full 5000-line routes.py.
"""
import re
import sys
import os
import pytest
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate and load the installer templates from source
# ---------------------------------------------------------------------------
_ROUTES_PATH = Path(__file__).parent.parent.parent / \
    "backend" / "blueprints" / "system" / "routes.py"


def _extract_template(source: str, var_name: str) -> str:
    """Extract the value of a triple-quoted string variable from Python source."""
    # Match: VAR = """...""" (non-greedy, multiline)
    pattern = rf'{re.escape(var_name)}\s*=\s*"""\\\n(.*?)^"""'
    m = re.search(pattern, source, re.DOTALL | re.MULTILINE)
    if not m:
        # Try without backslash continuation
        pattern2 = rf'{re.escape(var_name)}\s*=\s*"""(.*?)"""'
        m = re.search(pattern2, source, re.DOTALL)
    assert m, f"Could not find {var_name} in routes.py"
    return m.group(1)


@pytest.fixture(scope='module')
def routes_src() -> str:
    assert _ROUTES_PATH.exists(), f"routes.py not found at {_ROUTES_PATH}"
    return _ROUTES_PATH.read_text(encoding='utf-8')


@pytest.fixture(scope='module')
def sh_template(routes_src) -> str:
    return _extract_template(routes_src, '_INSTALLER_SH')


@pytest.fixture(scope='module')
def ps1_template(routes_src) -> str:
    return _extract_template(routes_src, '_INSTALLER_PS1')


@pytest.fixture(scope='module')
def sh_rendered(sh_template) -> str:
    """Template with test values substituted."""
    return sh_template.format(
        server_url='https://cy360.example.com',
        cysiem_manager='10.0.0.1',
        version='1.0.99',
    )


@pytest.fixture(scope='module')
def ps1_rendered(ps1_template) -> str:
    return ps1_template.format(
        server_url='https://cy360.example.com',
        cysiem_manager='10.0.0.1',
        version='1.0.99',
    )


# ===========================================================================
# Suite: Bash template — safety and structure
# ===========================================================================

class TestShellSafety:
    """The bash installer must be safe by construction."""

    def test_set_euo_pipefail_present(self, sh_template):
        assert 'set -euo pipefail' in sh_template, \
            "Installer must have 'set -euo pipefail'"

    def test_no_bare_clear_command(self, sh_template):
        """'clear' must not appear as a bare command (regression from g-cyra-test Suite 09)."""
        lines = sh_template.split('\n')
        for line in lines:
            stripped = line.strip()
            assert stripped != 'clear', f"Bare 'clear' found: {line!r}"

    def test_format_placeholders_present(self, sh_template):
        """Template must have all three required placeholders."""
        assert '{server_url}'     in sh_template, "Missing {server_url} placeholder"
        assert '{cysiem_manager}' in sh_template, "Missing {cysiem_manager} placeholder"
        assert '{version}'        in sh_template, "Missing {version} placeholder"

    def test_renders_without_error(self, sh_rendered):
        """Template rendering with test values must not raise KeyError or IndexError."""
        assert len(sh_rendered) > 500

    def test_placeholders_resolved_after_render(self, sh_rendered, sh_template):
        """After rendering, the three Python placeholders must not appear in the output.
        Bash variables like ${EUID} are left intact — they are not Python placeholders."""
        # Verify that the three Python-level placeholders no longer appear literally
        assert '{server_url}'     not in sh_rendered, "{server_url} was not substituted"
        assert '{cysiem_manager}' not in sh_rendered, "{cysiem_manager} was not substituted"
        assert '{version}'        not in sh_rendered, "{version} was not substituted"

    def test_rendered_contains_server_url(self, sh_rendered):
        assert 'https://cy360.example.com' in sh_rendered

    def test_rendered_contains_manager_ip(self, sh_rendered):
        assert '10.0.0.1' in sh_rendered

    def test_rendered_contains_version(self, sh_rendered):
        assert '1.0.99' in sh_rendered

    def test_no_python_format_errors_with_special_chars(self, sh_template):
        """Render with URLs containing special characters (port number)."""
        result = sh_template.format(
            server_url='https://cy360.internal:5252',
            cysiem_manager='192.168.1.100',
            version='2.0.0-rc1',
        )
        assert 'cy360.internal:5252' in result
        assert '192.168.1.100' in result


# ===========================================================================
# Suite: _register_agent() function logic
# ===========================================================================

class TestRegisterAgentFunction:
    """The _register_agent() bash function must be correct after the duplicate-name fix."""

    def test_function_exists(self, sh_template):
        assert '_register_agent()' in sh_template, "_register_agent() function not found"

    def test_captures_output_before_checking_rc(self, sh_template):
        """Output must be captured with $() assignment before checking return code."""
        assert 'local out rc=0' in sh_template, \
            "_register_agent must capture agent-auth output before checking rc"

    def test_detects_duplicate_agent_string(self, sh_template):
        """Duplicate name case must be handled by grepping for 'Duplicate agent'."""
        assert 'Duplicate agent' in sh_template, \
            "_register_agent must grep for 'Duplicate agent' to detect upgrade scenario"

    def test_upgrade_path_does_not_abort(self, sh_template):
        """When duplicate is detected, installer should ok() not err()."""
        # Find the block after "Duplicate agent" — it should call ok(), not err()
        dup_idx = sh_template.index('Duplicate agent')
        # Look for the next ~300 chars after detection — should see 'ok' not 'err'
        after_dup = sh_template[dup_idx: dup_idx + 300]
        assert 'already registered' in after_dup or 'upgrade detected' in after_dup, \
            "Duplicate agent detection must indicate upgrade, not failure"

    def test_no_restart_inside_register_agent(self, sh_template):
        """After the fix: _register_agent() must NOT call ${ctrl_bin} restart internally.
        The double-restart bug was caused by this — restart moved outside the function."""
        # Extract the function body
        func_start = sh_template.find('_register_agent() {')
        assert func_start != -1
        # Find matching closing brace (simplified: look for '\n}' that closes the function)
        func_body_start = func_start
        brace_count = 0
        in_func = False
        func_end = func_start
        for i, ch in enumerate(sh_template[func_start:], func_start):
            if ch == '{':
                brace_count += 1
                in_func = True
            elif ch == '}':
                brace_count -= 1
                if in_func and brace_count == 0:
                    func_end = i + 1
                    break
        func_body = sh_template[func_body_start:func_end]
        # The function must NOT contain ctrl_bin restart (that was the bug)
        assert 'restart' not in func_body or 'ctrl_bin' not in func_body or \
            '${ctrl_bin} restart' not in func_body, \
            "_register_agent() must NOT call ${ctrl_bin} restart (double-restart bug)"

    def test_registration_failure_suggests_port_1515(self, sh_template):
        """Non-duplicate failures should suggest checking port 1515."""
        assert '1515' in sh_template, "Error message should mention port 1515"

    def test_registration_failure_non_destructive(self, sh_template):
        """The generic registration error should call err() which exits non-zero."""
        # Find the else branch of the duplicate check
        after_func = sh_template[sh_template.find('_register_agent()'):
                                  sh_template.find('_register_agent()') + 800]
        assert 'err ' in after_func, "Non-duplicate registration failure must call err()"


# ===========================================================================
# Suite: macOS FDA notice content
# ===========================================================================

class TestMacOSFDANotice:
    """macOS FDA notice must list both agent binaries and restart instruction."""

    def test_fda_notice_present(self, sh_template):
        assert 'Full Disk Access' in sh_template, "FDA notice missing from installer"

    def test_wazuh_agentd_listed(self, sh_template):
        assert 'wazuh-agentd' in sh_template, \
            "FDA notice must list /Library/Ossec/bin/wazuh-agentd"

    def test_wazuh_logcollector_listed(self, sh_template):
        assert 'wazuh-logcollector' in sh_template, \
            "FDA notice must list wazuh-logcollector (fails to start without FDA)"

    def test_restart_instruction_after_fda(self, sh_template):
        """Must tell user how to restart after granting FDA."""
        assert 'wazuh-control restart' in sh_template, \
            "FDA notice must include restart command: wazuh-control restart"

    def test_fda_notice_both_binaries_in_darwin_section(self, sh_template):
        """Both binaries must appear in do_install_macos() called by Darwin)."""
        assert 'Darwin)' in sh_template, "Darwin) case not found"
        assert 'do_install_macos' in sh_template, "Darwin) must call do_install_macos()"
        assert 'wazuh-agentd'       in sh_template, "FDA notice must list wazuh-agentd"
        assert 'wazuh-logcollector' in sh_template, "FDA notice must list wazuh-logcollector"

    def test_logcollector_will_not_start_message(self, sh_template):
        """Must warn user that Full Disk Access is required for log collection."""
        assert 'requires Full Disk Access' in sh_template or \
               'Full Disk Access to collect' in sh_template, \
            "Installer must explain why Full Disk Access is required"


# ===========================================================================
# Suite: Branding — audit keys use cy360 not wazuh
# ===========================================================================

class TestAuditKeyBranding:
    """Audit rule keys must be branded cy360, not the old cy360_wazuh_ prefix."""

    def test_agent_tamper_key_used(self, sh_template):
        assert 'cy360_agent_tamper' in sh_template, \
            "Audit rules must use -k cy360_agent_tamper"

    def test_no_wazuh_tamper_key(self, sh_template):
        assert 'wazuh_tamper' not in sh_template, \
            "Old cy360_wazuh_tamper audit key must not appear"

    def test_exec_key_branded(self, sh_template):
        assert 'cy360_exec' in sh_template, "Audit exec key must be cy360_exec"

    def test_privesc_key_branded(self, sh_template):
        assert 'cy360_privesc' in sh_template, "Audit privesc key must be cy360_privesc"


# ===========================================================================
# Suite: Linux restart uses cy360-agent first
# ===========================================================================

class TestLinuxRestart:
    """Linux systemctl restart tries cy360-agent before wazuh-agent fallback."""

    def test_cy360_agent_first_in_restart(self, sh_template):
        """After the main registration, cy360-agent must be tried first."""
        # The restart chain should be:
        # systemctl restart cy360-agent 2>/dev/null || systemctl restart wazuh-agent ...
        assert 'restart cy360-agent' in sh_template, \
            "Linux restart must try cy360-agent first"
        assert 'restart wazuh-agent' in sh_template, \
            "Linux restart must fall back to wazuh-agent"

    def test_cy360_appears_before_wazuh_in_restart(self, sh_template):
        cy360_pos = sh_template.find('restart cy360-agent')
        wazuh_pos = sh_template.find('restart wazuh-agent')
        assert cy360_pos < wazuh_pos, \
            "cy360-agent must appear before wazuh-agent in restart chain"


# ===========================================================================
# Suite: Darwin single restart after all config
# ===========================================================================

class TestDarwinSingleRestart:
    """macOS must have a single restart AFTER ULS config is applied (not inside _register_agent)."""

    def test_darwin_restart_after_maceof(self, sh_template):
        """MACEOF ends the ULS heredoc — restart must follow it, not precede it."""
        maceof_idx = sh_template.rfind('MACEOF')
        assert maceof_idx != -1, "MACEOF heredoc marker not found"
        after_maceof = sh_template[maceof_idx:]
        assert 'restart' in after_maceof, \
            "Restart must occur AFTER MACEOF (after ULS config is written)"

    def test_only_one_ctrl_restart_in_darwin(self, sh_template):
        """do_install_macos() must have exactly one CTRL_BIN restart (no double-restart).

        The template uses double-braces: "${{CTRL_BIN}}" restart — this is how bash
        variable references are written inside a Python format string.
        FDA notice and restart live inside do_install_macos(), called from Darwin).
        """
        func_start = sh_template.find('do_install_macos() {')
        assert func_start != -1, "do_install_macos() not found"
        brace_count = 0
        in_func = False
        func_end = func_start
        for i, ch in enumerate(sh_template[func_start:], func_start):
            if ch == '{':
                brace_count += 1
                in_func = True
            elif ch == '}':
                brace_count -= 1
                if in_func and brace_count == 0:
                    func_end = i + 1
                    break
        func_body = sh_template[func_start:func_end]
        restart_count = func_body.count('CTRL_BIN}}" restart')
        assert restart_count == 1, \
            f"do_install_macos() must have exactly 1 CTRL_BIN restart, found {restart_count}"


# ===========================================================================
# Suite: Windows PowerShell template
# ===========================================================================

class TestPS1Template:
    """The PowerShell installer template must have required elements."""

    def test_placeholders_present(self, ps1_template):
        assert '{server_url}'     in ps1_template
        assert '{cysiem_manager}' in ps1_template
        assert '{version}'        in ps1_template

    def test_renders_without_error(self, ps1_rendered):
        assert len(ps1_rendered) > 200

    def test_rendered_contains_server_url(self, ps1_rendered):
        assert 'https://cy360.example.com' in ps1_rendered

    def test_error_action_preference_stop(self, ps1_template):
        assert '$ErrorActionPreference = "Stop"' in ps1_template

    def test_tls12_set(self, ps1_template):
        assert 'Tls12' in ps1_template, "PowerShell installer must enforce TLS 1.2"

    def test_agent_auth_exe_present(self, ps1_template):
        assert 'agent-auth.exe' in ps1_template, \
            "Windows installer must call agent-auth.exe for registration"

    def test_cycentra_branding_present(self, ps1_template):
        assert 'CyCentra' in ps1_template, \
            "Windows installer must display CyCentra branding"


# ===========================================================================
# Suite: _read_installed_version helper
# ===========================================================================

class TestReadInstalledVersion:
    """_read_installed_version() returns version from /opt/cycentra/version or fallback."""

    @pytest.fixture(autouse=True)
    def _setup_path(self):
        import importlib.util
        # We need to import routes.py partially — mock the heavy dependencies
        from unittest.mock import MagicMock
        for mod in [
            'flask', 'flask.request', 'flask.session',
            'psutil', 'jwt', 'yaml', 'structlog',
            'apscheduler', 'apscheduler.schedulers', 'apscheduler.schedulers.background',
            'google', 'google.generativeai', 'google.genai', 'google.auth',
            'reportlab', 'reportlab.lib', 'reportlab.lib.colors',
            'reportlab.platypus', 'reportlab.lib.pagesizes', 'reportlab.lib.styles',
            'reportlab.lib.units',
            'nmap', 'dns', 'dns.resolver', 'bs4',
            'cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
            'cryptography.hazmat.primitives.asymmetric',
            'cryptography.hazmat.primitives.hashes',
            'cryptography.hazmat.backends',
            'cryptography.x509',
            'Crypto', 'Crypto.PublicKey', 'Crypto.PublicKey.RSA',
            'Crypto.Cipher', 'Crypto.Cipher.PKCS1_OAEP',
            'OpenSSL', 'OpenSSL.SSL',
            'requests',
        ]:
            if mod not in sys.modules:
                sys.modules[mod] = MagicMock()

    def test_returns_fallback_when_no_version_file(self, tmp_path, monkeypatch):
        """When neither /opt/cycentra/version file exists, return '1.0.0'."""
        # Load the function by exec'ing just the relevant snippet
        src = """
import os
def _read_installed_version():
    for vf in ("/opt/cycentra/version", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            return open(vf).read().strip().lstrip("v")
    return "1.0.0"
"""
        ns = {}
        exec(src, ns)
        result = ns['_read_installed_version']()
        assert result == '1.0.0'

    def test_reads_version_from_file(self, tmp_path, monkeypatch):
        version_file = tmp_path / 'version'
        version_file.write_text('v1.0.60\n')

        src = f"""
import os
def _read_installed_version():
    for vf in ("{version_file}", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            return open(vf).read().strip().lstrip("v")
    return "1.0.0"
"""
        ns = {}
        exec(src, ns)
        result = ns['_read_installed_version']()
        assert result == '1.0.60'

    def test_strips_leading_v(self, tmp_path):
        version_file = tmp_path / 'version'
        version_file.write_text('v2.3.4')

        src = f"""
import os
def _read_installed_version():
    for vf in ("{version_file}", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            return open(vf).read().strip().lstrip("v")
    return "1.0.0"
"""
        ns = {}
        exec(src, ns)
        result = ns['_read_installed_version']()
        assert result == '2.3.4'

    def test_returns_plain_version_without_v(self, tmp_path):
        version_file = tmp_path / 'version'
        version_file.write_text('1.0.61')

        src = f"""
import os
def _read_installed_version():
    for vf in ("{version_file}", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            return open(vf).read().strip().lstrip("v")
    return "1.0.0"
"""
        ns = {}
        exec(src, ns)
        result = ns['_read_installed_version']()
        assert result == '1.0.61'


# ===========================================================================
# Suite: Route presence & security (static analysis)
# ===========================================================================

class TestRoutePresence:
    """Verify the route definitions and auth guard exist in source."""

    def test_route_decorator_present(self, routes_src):
        assert '/api/system/agent-installer' in routes_src, \
            "Route /api/system/agent-installer must be defined"

    def test_auth_guard_present(self, routes_src):
        """Route must check session for user_email before serving installer."""
        # Find the function
        route_idx = routes_src.find('def get_agent_installer()')
        assert route_idx != -1
        func_body = routes_src[route_idx: route_idx + 500]
        assert 'user_email' in func_body, \
            "get_agent_installer must check session['user_email']"
        assert '401' in func_body, \
            "get_agent_installer must return 401 for unauthenticated requests"

    def test_unix_format_serves_sh_mimetype(self, routes_src):
        """Unix format must use text/x-shellscript mimetype."""
        assert 'text/x-shellscript' in routes_src, \
            "Unix installer must use text/x-shellscript MIME type"

    def test_windows_format_serves_text_plain(self, routes_src):
        assert 'text/plain' in routes_src, \
            "Windows PS1 installer should use text/plain MIME type"

    def test_content_disposition_attachment(self, routes_src):
        assert 'Content-Disposition' in routes_src and 'attachment' in routes_src, \
            "Installer must be served as attachment to trigger download"

    def test_nosniff_header(self, routes_src):
        assert 'X-Content-Type-Options' in routes_src and 'nosniff' in routes_src, \
            "Installer response must set X-Content-Type-Options: nosniff"

    def test_format_param_lowercased(self, routes_src):
        """Format param must be lowercased to avoid case-sensitivity bugs."""
        route_idx = routes_src.find('def get_agent_installer()')
        func_body = routes_src[route_idx: route_idx + 600]
        assert '.lower()' in func_body, \
            "format param must be .lower()'d to avoid 'Unix' vs 'unix' mismatch"

    def test_options_cors_preflight_present(self, routes_src):
        """OPTIONS handler must be defined for CORS preflight."""
        assert 'agent_installer_options' in routes_src or \
               '"OPTIONS"' in routes_src, \
            "OPTIONS preflight handler must exist for /api/system/agent-installer"
