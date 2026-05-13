"""
blueprints/platform/state.py
==============================
Persistent state for platform module installs.
Reads/writes /opt/cycentra/modules_state.json.
"""

import json
import logging

from core.config import MODULES_STATE

logger = logging.getLogger(__name__)


def load_state() -> dict:
    """Return the current module install state dict."""
    try:
        if MODULES_STATE.exists():
            return json.loads(MODULES_STATE.read_text())
    except Exception as e:
        logger.error(f"[State] Load error: {e}")
    return {}


def save_state(state: dict):
    """Persist the module install state dict to disk."""
    try:
        MODULES_STATE.parent.mkdir(parents=True, exist_ok=True)
        MODULES_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        logger.error(f"[State] Save error: {e}")
