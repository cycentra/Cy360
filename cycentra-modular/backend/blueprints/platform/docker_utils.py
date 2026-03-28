"""
blueprints/platform/docker_utils.py
=====================================
Docker helpers used by the platform install/uninstall flow.
"""

import json

from core.config import MODULES_DIR
from core.helpers import run


def docker_containers_running(module_id: str) -> bool:
    """Return True if at least one container for the module is in Running state."""
    module_dir = MODULES_DIR / module_id
    if not module_dir.exists():
        return False

    rc, out, _ = run("docker compose ps --format json", cwd=str(module_dir))
    if rc != 0 or not out:
        return False

    try:
        for line in [l for l in out.splitlines() if l.strip().startswith("{")]:
            obj = json.loads(line)
            if obj.get("State") == "running" or "Up" in obj.get("Status", ""):
                return True
    except Exception:
        # Fallback: parse plain text output
        rc2, out2, _ = run("docker compose ps", cwd=str(module_dir))
        return "Up" in out2

    return False
