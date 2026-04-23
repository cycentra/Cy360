"""
Regression test — _PIP_BSP unbound variable when UI triggers --update

Bug:
  `_PIP_BSP` was initialised inside the INFRASTRUCTURE block
  (`if [[ "$MODE" != "update" ]]; then`).  The APP BLOCK (runs in all
  modes) uses `${_PIP_BSP}` in two places:
    - line ~657  pip3 install ${_PIP_BSP} redis  (CySIEM → Redis bridge)
    - line ~1767 pip3 install … ${_PIP_BSP} …    (backend wheel install)
  With `set -euo pipefail` a reference to an uninitialised variable aborts
  the script.  Manual `--update` ran the old on-disk script; the UI button
  downloads the LATEST release and runs it, exposing the regression.

Root cause: variable scoped to infra block, consumed in all-modes block.

Fix: add a `_PIP_BSP` detection block immediately after `fi  # end INFRA block`
so the variable is always set before the APP BLOCK executes.

These tests FAIL against the unfixed script and PASS after the fix.
"""

import re
import subprocess
from pathlib import Path

SETUP_SH = Path(__file__).parent.parent.parent / "cycentra-setup.sh"

# ── helpers ───────────────────────────────────────────────────────────────────

def _read_lines() -> list[str]:
    return SETUP_SH.read_text().splitlines()


def _line_of(lines: list[str], pattern: str) -> int:
    """Return 1-based line number of first line matching `pattern`, or -1."""
    for i, ln in enumerate(lines, start=1):
        if re.search(pattern, ln):
            return i
    return -1


# ── Test 1: _PIP_BSP must be initialised before APP BLOCK in all code paths ──

def test_pip_bsp_initialised_before_app_block():
    """
    The APP BLOCK comment marks where mode-independent code starts.
    _PIP_BSP must be assigned (either a fresh detection OR a default empty
    assignment) on a line that precedes the APP BLOCK marker and is NOT
    exclusively inside the INFRA block.

    Specifically: there must be a `_PIP_BSP=` assignment at or before the
    line that says `fi  # end INFRA block` — i.e. in the global scope that
    runs regardless of MODE.
    """
    lines = _read_lines()

    infra_end  = _line_of(lines, r'fi\s*#\s*end INFRA block')
    app_block  = _line_of(lines, r'APP BLOCK')
    infra_start = _line_of(lines, r'INFRASTRUCTURE BLOCK')

    assert infra_end  > 0, "Could not locate 'fi  # end INFRA block' marker"
    assert app_block  > 0, "Could not locate 'APP BLOCK' marker"
    assert infra_start > 0, "Could not locate 'INFRASTRUCTURE BLOCK' marker"

    # Find the last `_PIP_BSP=` assignment that is AT OR AFTER `fi  # end INFRA block`
    # (i.e. in global / app-block scope, not inside the infra block).
    assignments_after_infra_end = [
        i for i, ln in enumerate(lines, start=1)
        if re.search(r'^\s*_PIP_BSP=', ln) and i >= infra_end
    ]

    assert assignments_after_infra_end, (
        f"_PIP_BSP is never (re-)initialised at or after line {infra_end} "
        f"('fi  # end INFRA block').  In --update mode the INFRA block is "
        f"skipped so the variable is unbound when the APP BLOCK uses it.  "
        f"Add a _PIP_BSP detection block immediately after 'fi  # end INFRA block'."
    )


# ── Test 2: every ${_PIP_BSP} reference in the APP BLOCK has the variable set ─

def test_pip_bsp_set_before_first_use_in_app_block():
    """
    The first use of ${_PIP_BSP} in the APP BLOCK must come AFTER the last
    out-of-infra-block initialisation line.
    """
    lines = _read_lines()

    infra_end = _line_of(lines, r'fi\s*#\s*end INFRA block')
    assert infra_end > 0, "Could not locate 'fi  # end INFRA block'"

    last_init_after_infra = max(
        (i for i, ln in enumerate(lines, start=1)
         if re.search(r'^\s*_PIP_BSP=', ln) and i >= infra_end),
        default=-1,
    )
    assert last_init_after_infra > 0, (
        "_PIP_BSP has no initialisation in app-block scope — see test above."
    )

    first_use_after_infra = min(
        (i for i, ln in enumerate(lines, start=1)
         if re.search(r'\$\{?_PIP_BSP\}?', ln) and i > infra_end),
        default=999999,
    )

    assert last_init_after_infra < first_use_after_infra, (
        f"_PIP_BSP is first used at line {first_use_after_infra} but its "
        f"last app-block-scope initialisation is at line {last_init_after_infra}. "
        f"Move the detection block to before line {first_use_after_infra}."
    )


# ── Test 3: bash syntax + set -u simulation (subprocess) ─────────────────────

def test_update_mode_no_unbound_variable(tmp_path):
    """
    Synthesise a minimal script that reproduces the failure path:
      - set -euo pipefail
      - simulate the structure: infra block skipped (MODE=update)
      - reference ${_PIP_BSP} in the app block

    Then verify that the fix (initialising _PIP_BSP before the app block)
    prevents the 'unbound variable' exit.

    This test FAILS if the only _PIP_BSP= assignment is inside the infra block,
    and PASSES once there is an assignment in the always-executed scope.
    """
    lines = _read_lines()
    infra_end = _line_of(lines, r'fi\s*#\s*end INFRA block')
    assert infra_end > 0

    # Collect every _PIP_BSP= assignment that is NOT inside the infra block
    # (infra block: from the `if [[ "$MODE" != "update" ]]` to `fi  # end INFRA block`)
    infra_start = _line_of(lines, r'INFRASTRUCTURE BLOCK')
    out_of_infra = [
        ln.strip() for i, ln in enumerate(lines, start=1)
        if re.search(r'^\s*_PIP_BSP=', ln)
        and not (infra_start < i < infra_end)
    ]

    # Build a tiny script: set -eu, simulate update mode, run the init lines,
    # then try to expand the variable — must not crash.
    init_block = "\n".join(out_of_infra) if out_of_infra else ""
    script = f"""\
#!/bin/bash
set -euo pipefail
MODE=update
{init_block}
# Simulate the APP BLOCK usage (no actual pip3 call needed — just expansion)
_flag=${{_PIP_BSP}}
echo "OK: _PIP_BSP='${{_flag}}'"
"""
    script_path = tmp_path / "sim_update.sh"
    script_path.write_text(script)

    result = subprocess.run(
        ["bash", str(script_path)],
        capture_output=True, text=True
    )
    assert result.returncode == 0, (
        f"Simulated --update mode exited {result.returncode}.\n"
        f"stderr: {result.stderr}\n"
        f"This means _PIP_BSP is unbound in the app-block scope.\n"
        f"Fix: add '_PIP_BSP=...' detection after 'fi  # end INFRA block'."
    )
