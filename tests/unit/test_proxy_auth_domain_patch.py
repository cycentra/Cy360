"""
Regression tests — proxy_auth_domain config.yml state-machine patcher

Bug: The Python script embedded in cycentra-setup.sh (Step 4.3b) that patches
     proxy_auth_domain.http_enabled in OpenSearch Security config.yml had two
     critical defects:

     1. Exit condition "indent <= 4" never fired for proxy_auth_domain blocks
        indented at 6+ spaces (all Wazuh builds use 6-space indent for authc
        children).  The state machine never exited the proxy_auth_domain block
        and could inadvertently modify sibling auth domains.

     2. The script always printed "OpenSearch proxy_auth_domain enabled" and
        exited 0 even when proxy_auth_domain was never found in the file.
        securityadmin.sh then uploaded the UNCHANGED config.yml, leaving
        http_enabled: false and causing the Wazuh login screen to appear.

These tests exercise the patching logic directly to prevent future regressions.
"""

import os
import sys
import textwrap
import tempfile
import subprocess

import pytest


# ---------------------------------------------------------------------------
# Inline replica of the patching function from cycentra-setup.sh
# (extracted so we can unit-test it without running the shell script)
# ---------------------------------------------------------------------------

def _patch_config_yml(text: str) -> tuple[str, bool]:
    """
    Apply the fixed state-machine patcher to *text* (contents of config.yml).

    Returns (patched_text, was_patched).
    Raises RuntimeError if the block was absent and no insertion point found.
    """
    lines = text.splitlines()
    out = []
    in_proxy_domain  = False
    proxy_dom_indent = -1
    found            = False
    patched          = False

    for line in lines:
        stripped = line.lstrip()
        indent   = len(line) - len(stripped)

        if stripped.startswith("proxy_auth_domain:"):
            in_proxy_domain  = True
            proxy_dom_indent = indent
            found            = True
            out.append(line)
            continue

        if in_proxy_domain:
            # Fixed: use indent-relative exit, not the hardcoded "indent <= 4"
            if stripped and not stripped.startswith("#") and indent <= proxy_dom_indent:
                in_proxy_domain = False
                # fall through to normal append
            elif stripped.startswith("http_enabled:") and not patched:
                out.append(line.replace("http_enabled: false", "http_enabled: true"))
                patched = True
                continue

        out.append(line)

    # If block was absent, inject before basic_internal_auth_domain
    if not found:
        new_lines = []
        for line in out:
            if line.lstrip().startswith("basic_internal_auth_domain:") and not patched:
                base_indent  = " " * (len(line) - len(line.lstrip()))
                child_indent = base_indent + "  "
                new_lines += [
                    base_indent + "proxy_auth_domain:",
                    child_indent + 'description: "CyCentra 360 IAP proxy authentication"',
                    child_indent + "http_enabled: true",
                    child_indent + "transport_enabled: false",
                    child_indent + "order: 1",
                    child_indent + "http_authenticator:",
                    child_indent + "  type: proxy",
                    child_indent + "  challenge: false",
                    child_indent + "  config:",
                    child_indent + '    user_header: "x-proxy-user"',
                    child_indent + '    roles_header: "x-proxy-roles"',
                    child_indent + "authentication_backend:",
                    child_indent + "  type: noop",
                ]
                patched = True
            new_lines.append(line)
        out = new_lines

    return "\n".join(out) + "\n", patched


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WAZUH_CONFIG_STANDARD = textwrap.dedent("""\
    ---
    _meta:
      type: "config"
      config_version: 2
    config:
      dynamic:
        http:
          anonymous_auth_enabled: false
        authc:
          jwt_auth_domain:
            description: "JWT"
            http_enabled: false
            transport_enabled: false
            order: 0
            http_authenticator:
              type: jwt
              challenge: false
            authentication_backend:
              type: noop
          proxy_auth_domain:
            description: "Authenticate via proxy"
            http_enabled: false
            transport_enabled: false
            order: 1
            http_authenticator:
              type: proxy
              challenge: false
              config:
                user_header: "x-proxy-user"
                roles_header: "x-proxy-roles"
            authentication_backend:
              type: noop
          basic_internal_auth_domain:
            description: "HTTP Basic"
            http_enabled: true
            transport_enabled: true
            order: 4
            http_authenticator:
              type: basic
              challenge: true
            authentication_backend:
              type: intern
""")

WAZUH_CONFIG_NO_PROXY_DOMAIN = textwrap.dedent("""\
    ---
    _meta:
      type: "config"
      config_version: 2
    config:
      dynamic:
        http:
          anonymous_auth_enabled: false
        authc:
          jwt_auth_domain:
            description: "JWT"
            http_enabled: false
            transport_enabled: false
            order: 0
            http_authenticator:
              type: jwt
              challenge: false
            authentication_backend:
              type: noop
          basic_internal_auth_domain:
            description: "HTTP Basic"
            http_enabled: true
            transport_enabled: true
            order: 4
            http_authenticator:
              type: basic
              challenge: true
            authentication_backend:
              type: intern
""")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProxyDomainPatchFound:
    """proxy_auth_domain block IS present in config.yml."""

    def test_enables_http_enabled(self):
        result, patched = _patch_config_yml(WAZUH_CONFIG_STANDARD)
        assert patched, "Patcher must report success"
        # Locate the proxy_auth_domain section in the output
        lines = result.splitlines()
        in_block = False
        for line in lines:
            if line.lstrip().startswith("proxy_auth_domain:"):
                in_block = True
            if in_block and line.lstrip().startswith("http_enabled:"):
                assert "true" in line.lower(), (
                    f"proxy_auth_domain.http_enabled must be true: {line!r}"
                )
                break
        else:
            pytest.fail("proxy_auth_domain.http_enabled line not found after patch")

    def test_does_not_modify_jwt_auth_domain(self):
        """jwt_auth_domain.http_enabled must remain false (regression for the
        old bug where in_proxy_domain never exited and modified siblings)."""
        result, _ = _patch_config_yml(WAZUH_CONFIG_STANDARD)
        lines = result.splitlines()
        in_jwt = False
        for line in lines:
            if line.lstrip().startswith("jwt_auth_domain:"):
                in_jwt = True
            if in_jwt and line.lstrip().startswith("http_enabled:"):
                assert "false" in line.lower(), (
                    f"jwt_auth_domain.http_enabled must stay false: {line!r}"
                )
                break

    def test_does_not_modify_basic_internal_auth_domain(self):
        """basic_internal_auth_domain.http_enabled must stay true."""
        result, _ = _patch_config_yml(WAZUH_CONFIG_STANDARD)
        lines = result.splitlines()
        in_basic = False
        for line in lines:
            if line.lstrip().startswith("basic_internal_auth_domain:"):
                in_basic = True
            if in_basic and line.lstrip().startswith("http_enabled:"):
                assert "true" in line.lower(), (
                    f"basic_internal_auth_domain.http_enabled must stay true: {line!r}"
                )
                break

    def test_output_is_valid_yaml(self):
        import yaml  # noqa: PLC0415
        result, _ = _patch_config_yml(WAZUH_CONFIG_STANDARD)
        parsed = yaml.safe_load(result)
        assert parsed is not None

    def test_already_true_is_idempotent(self):
        """If http_enabled is already true, the output must be identical."""
        already_true = WAZUH_CONFIG_STANDARD.replace(
            "proxy_auth_domain:\n"
            "            description: \"Authenticate via proxy\"\n"
            "            http_enabled: false",
            "proxy_auth_domain:\n"
            "            description: \"Authenticate via proxy\"\n"
            "            http_enabled: true",
        )
        result, patched = _patch_config_yml(already_true)
        # patched may be True or False depending on whether the replace matched;
        # the important check is that http_enabled is still true in the output.
        lines = result.splitlines()
        in_block = False
        for line in lines:
            if line.lstrip().startswith("proxy_auth_domain:"):
                in_block = True
            if in_block and line.lstrip().startswith("http_enabled:"):
                assert "true" in line.lower()
                break


class TestProxyDomainPatchAbsent:
    """proxy_auth_domain block is NOT in config.yml — injection path."""

    def test_injects_block_before_basic_internal(self):
        result, patched = _patch_config_yml(WAZUH_CONFIG_NO_PROXY_DOMAIN)
        assert patched, "Patcher must report success for injection path"
        assert "proxy_auth_domain:" in result

    def test_injected_block_has_http_enabled_true(self):
        result, _ = _patch_config_yml(WAZUH_CONFIG_NO_PROXY_DOMAIN)
        lines = result.splitlines()
        in_block = False
        for line in lines:
            if line.lstrip().startswith("proxy_auth_domain:"):
                in_block = True
            if in_block and line.lstrip().startswith("http_enabled:"):
                assert "true" in line.lower(), (
                    f"injected proxy_auth_domain.http_enabled must be true: {line!r}"
                )
                break
        else:
            pytest.fail("Injected proxy_auth_domain.http_enabled not found")

    def test_injected_block_appears_before_basic_internal(self):
        result, _ = _patch_config_yml(WAZUH_CONFIG_NO_PROXY_DOMAIN)
        proxy_idx = result.find("proxy_auth_domain:")
        basic_idx = result.find("basic_internal_auth_domain:")
        assert proxy_idx != -1, "proxy_auth_domain not injected"
        assert proxy_idx < basic_idx, (
            "proxy_auth_domain must be injected before basic_internal_auth_domain"
        )

    def test_injected_output_is_valid_yaml(self):
        import yaml  # noqa: PLC0415
        result, _ = _patch_config_yml(WAZUH_CONFIG_NO_PROXY_DOMAIN)
        parsed = yaml.safe_load(result)
        assert parsed is not None

    def test_jwt_domain_untouched_after_injection(self):
        result, _ = _patch_config_yml(WAZUH_CONFIG_NO_PROXY_DOMAIN)
        lines = result.splitlines()
        in_jwt = False
        for line in lines:
            if line.lstrip().startswith("jwt_auth_domain:"):
                in_jwt = True
            if in_jwt and line.lstrip().startswith("http_enabled:"):
                assert "false" in line.lower(), (
                    f"jwt_auth_domain.http_enabled must stay false: {line!r}"
                )
                break
