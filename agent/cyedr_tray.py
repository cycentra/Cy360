#!/usr/bin/env python3
"""
CyCentra 360 — CyEDR System Tray

Per-user, unprivileged companion to cyedr_agent.py. Shows a menu-bar/tray
icon indicating whether CyEDR is running and protecting this endpoint, and
offers two actions:
  - Run Scan Now       — triggers an on-demand YARA scan (low risk, no password)
  - Stop/Exit CyEDR...  — requires the admin password set in Cy360 -> EDR
                          Policies -> Tamper Protection, if one has been set

This process never talks to the Cy360 platform directly, holds no enrollment
token, and has no network access requirement. It only ever reaches the
locally-running cyedr_agent.py service over a local IPC channel — a Unix
domain socket on Linux/macOS, a named pipe on Windows — using the low-value
shared ipc_token dropped by the agent. The admin password itself is typed by
the local user into the Stop dialog and handed to the agent, which verifies
it locally against a bcrypt hash; this process never stores or sees the hash.

Built as a separate PyInstaller binary from cyedr_agent.py on purpose — see
agent-packages/build-edr-packages.sh. The agent runs as a privileged headless
service (root LaunchDaemon / SYSTEM service) with no GUI session; this tray
runs per-user, unprivileged, autostarted at login.
"""
import json
import os
import platform
import socket
import threading
import time

OS_TYPE = platform.system().upper()

# Must match Config.ipc_dir's default in cyedr_agent.py (sibling of edr_home).
# EDR_HOME itself is locked to root-only traversal by the installer (it holds
# the enrollment token in config.json) — this sibling directory is the one
# piece of agent state deliberately made reachable by any local user.
if OS_TYPE == "WINDOWS":
    _DEFAULT_IPC_DIR = r"C:\Program Files\CyCentra\edr-ipc"
    _PIPE_NAME       = r"\\.\pipe\CyEDRAgent"
else:
    _DEFAULT_IPC_DIR = "/opt/cycentra/edr-ipc"

_SOCKET_NAME  = "agent.sock"
_POLL_SECONDS = 10

_COLOR_PROTECTED   = (0, 200, 120, 255)    # CyCentra brand accent green
_COLOR_UNPROTECTED = (255, 176, 0, 255)    # amber — running, no admin password set
_COLOR_UNREACHABLE = (220, 50, 50, 255)    # red — agent not responding


class AgentClient:
    """Thin IPC client. One request/response per call, short timeout — the
    tray never blocks its UI thread waiting on the agent."""

    def __init__(self, ipc_dir: str = _DEFAULT_IPC_DIR):
        self._ipc_dir = ipc_dir
        self._token = self._load_token()

    def _load_token(self) -> str:
        try:
            with open(os.path.join(self._ipc_dir, "ipc.token")) as f:
                return f.read().strip()
        except Exception:
            return ""

    def _request(self, payload: dict, timeout: float = 10.0) -> dict:
        if not self._token:
            self._token = self._load_token()
        payload = {**payload, "token": self._token}
        if OS_TYPE == "WINDOWS":
            return self._request_windows(payload, timeout)
        return self._request_unix(payload, timeout)

    def _request_unix(self, payload: dict, timeout: float) -> dict:
        sock_path = os.path.join(self._ipc_dir, _SOCKET_NAME)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(sock_path)
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        finally:
            s.close()

    def _request_windows(self, payload: dict, timeout: float) -> dict:
        try:
            import win32file
            import win32pipe
        except ImportError:
            return {"ok": False, "error": "pywin32 not available"}
        handle = None
        try:
            handle = win32file.CreateFile(
                _PIPE_NAME, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            win32file.WriteFile(handle, json.dumps(payload).encode("utf-8"))
            _, data = win32file.ReadFile(handle, 65536)
            return json.loads(data.decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        finally:
            if handle is not None:
                try:
                    win32file.CloseHandle(handle)
                except Exception:
                    pass

    def status(self) -> dict:
        return self._request({"op": "status"}, timeout=5)

    def scan(self, path: str = "/") -> dict:
        return self._request({"op": "scan", "path": path}, timeout=10)

    def stop(self, password: str) -> dict:
        return self._request({"op": "stop", "password": password}, timeout=10)


def _make_icon_image(color):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((4, 4, 60, 60), fill=color)
    d.text((22, 18), "C", fill="white")
    return img


def _tooltip(status_resp: dict) -> str:
    if not status_resp.get("ok"):
        return "CyEDR — agent unreachable"
    hostname = status_resp.get("hostname", "this device")
    if status_resp.get("protected"):
        return f"CyEDR — protecting {hostname}"
    return f"CyEDR — running on {hostname} (no admin password set)"


# ── Windows / Linux (pystray) ────────────────────────────────────────────────
def run_pystray(client: AgentClient):
    import pystray
    from pystray import MenuItem as Item

    state = {"resp": {}}

    def _current_color():
        resp = state["resp"]
        if not resp.get("ok"):
            return _COLOR_UNREACHABLE
        return _COLOR_PROTECTED if resp.get("protected") else _COLOR_UNPROTECTED

    def _notify(icon_, title, message):
        try:
            icon_.notify(message, title)
        except Exception:
            pass

    def _prompt_password():
        try:
            import tkinter as tk
            from tkinter import simpledialog, messagebox
        except Exception:
            return None
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        # A stopped agent has no running process left to serve a "start"
        # command back to this tray — recovery needs local admin access to
        # this machine. Surfaced here, before the password prompt, so there
        # are no surprises about what this action actually does.
        proceed = messagebox.askokcancel(
            "CyEDR — Stop/Exit",
            "Stopping CyEDR requires local admin access to this machine to "
            "restart it afterward — it cannot be undone from this tray.\n\nContinue?",
            parent=root,
        )
        if not proceed:
            root.destroy()
            return None
        pwd = simpledialog.askstring(
            "CyEDR — Stop/Exit",
            "Enter the CyEDR admin password (set in Cy360 -> EDR Policies -> Tamper Protection):",
            show="*", parent=root,
        )
        root.destroy()
        return pwd

    def on_scan(icon_, _item):
        resp = client.scan()
        _notify(icon_, "CyEDR Scan",
                "Scan started — results will appear on the Cy360 dashboard."
                if resp.get("ok") else f"Scan request failed: {resp.get('error', 'unknown error')}")

    def on_stop(icon_, _item):
        pwd = _prompt_password()
        if pwd is None:
            return
        resp = client.stop(pwd)
        if resp.get("ok"):
            _notify(icon_, "CyEDR", "Stopping CyEDR...")
        else:
            _notify(icon_, "CyEDR", f"Stop denied: {resp.get('error', 'incorrect password')}")

    def poll_loop(icon_):
        while True:
            state["resp"] = client.status()
            icon_.icon  = _make_icon_image(_current_color())
            icon_.title = _tooltip(state["resp"])
            time.sleep(_POLL_SECONDS)

    menu = pystray.Menu(
        Item(lambda _i: _tooltip(state["resp"]), None, enabled=False),
        pystray.Menu.SEPARATOR,
        Item("Run Scan Now", on_scan),
        Item("Stop/Exit CyEDR...", on_stop),
        pystray.Menu.SEPARATOR,
        Item("About CyCentra 360",
             lambda icon_, _i: _notify(icon_, "CyCentra 360", "CyEDR Endpoint Protection")),
    )
    icon = pystray.Icon("cyedr", _make_icon_image(_COLOR_UNREACHABLE), "CyEDR", menu)
    threading.Thread(target=poll_loop, args=(icon,), daemon=True).start()
    icon.run()


# ── macOS (rumps) ─────────────────────────────────────────────────────────────
def _activate_app():
    """Bring this process to the front so its next window/alert can actually
    receive keystrokes. rumps runs the app under NSApplicationActivationPolicy
    Accessory (menu-bar app, no Dock icon, no Info.plist since this ships as a
    bare PyInstaller binary, not a .app bundle) — accessory apps are not
    automatically made key/frontmost when they open a window, so without this
    call rumps.Window's text field renders but silently never receives
    keyboard input (keystrokes keep going to whatever app was frontmost
    before the click). Must be called right before every rumps.alert/
    rumps.Window call, not just once at startup — activation is not sticky."""
    try:
        from AppKit import NSApplication
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
    except Exception:
        pass


def _disable_app_nap():
    """Exempt this process from macOS App Nap.

    This is a background, no-Dock-icon "accessory" app that's never the
    frontmost window and has no visible UI most of the time — exactly the
    profile App Nap targets for throttling. Left unexempted, the rumps.Timer
    driving poll() below can get silently throttled or paused by the OS after
    the process has sat backgrounded for a while: the process stays alive
    (matches what was observed — low but nonzero CPU, no crash) but the menu
    bar icon stops refreshing and shows a stale status (in this case stuck on
    the "unreachable" red the agent last actually reported before macOS
    throttled the timer) until something external touches the process again.
    The returned activity token MUST be kept alive for the process lifetime —
    NSProcessInfo only honors the exemption while a reference to it exists;
    letting it get garbage-collected re-enables App Nap immediately."""
    try:
        from Foundation import NSProcessInfo, NSActivityUserInitiated
        return NSProcessInfo.processInfo().beginActivityWithOptions_reason_(
            NSActivityUserInitiated, "CyEDR tray polls agent status every 10s in the background"
        )
    except Exception:
        return None


def run_rumps(client: AgentClient):
    import rumps
    _app_nap_activity = _disable_app_nap()  # noqa: F841 — keep-alive reference, see docstring

    class CyEDRTrayApp(rumps.App):
        def __init__(self):
            super().__init__("CyEDR", title="\U0001F534 CyEDR", quit_button=None)
            self.menu = ["Run Scan Now", "Stop/Exit CyEDR...", None, "About CyCentra 360"]
            self._resp = {}
            rumps.Timer(self.poll, _POLL_SECONDS).start()
            self.poll(None)

        def poll(self, _timer):
            self._resp = client.status()
            if not self._resp.get("ok"):
                dot = "\U0001F534"          # red
            elif self._resp.get("protected"):
                dot = "\U0001F7E2"          # green
            else:
                dot = "\U0001F7E1"          # amber
            self.title = f"{dot} CyEDR"

        @rumps.clicked("Run Scan Now")
        def scan(self, _sender):
            resp = client.scan()
            rumps.notification(
                "CyEDR Scan", "",
                "Scan started — results will appear on the Cy360 dashboard."
                if resp.get("ok") else f"Scan request failed: {resp.get('error', 'unknown error')}",
            )

        @rumps.clicked("Stop/Exit CyEDR...")
        def stop(self, _sender):
            # A stopped agent has no running process left to serve a "start"
            # command back to this tray — recovery needs local admin access
            # to this machine. Surfaced before the password prompt so there
            # are no surprises about what this action actually does. The
            # actual recovery command is spelled out here (not just logged to
            # a file nobody will think to check once the process has exited).
            _activate_app()
            proceed = rumps.alert(
                title="CyEDR — Stop/Exit",
                message=("Stopping CyEDR requires local admin access to this machine "
                          "to restart it afterward — it cannot be undone from this tray.\n\n"
                          "To restart later, run in Terminal:\n"
                          "sudo launchctl bootstrap system /Library/LaunchDaemons/com.cycentra.edr.plist"),
                ok="Continue", cancel="Cancel",
            )
            if proceed != 1:
                return
            _activate_app()
            window = rumps.Window(
                message="Enter the CyEDR admin password (set in Cy360 -> EDR Policies -> Tamper Protection):",
                title="Stop/Exit CyEDR",
                default_text="", ok="Stop", cancel="Cancel",
                secure=True, dimensions=(280, 20),
            )
            result = window.run()
            if not result.clicked:
                return
            resp = client.stop(result.text)
            if resp.get("ok"):
                rumps.notification("CyEDR", "", "Stopping CyEDR...")
            else:
                rumps.notification("CyEDR", "", f"Stop denied: {resp.get('error', 'incorrect password')}")

        @rumps.clicked("About CyCentra 360")
        def about(self, _sender):
            rumps.alert("CyCentra 360", "CyEDR Endpoint Protection — system tray companion.")

    CyEDRTrayApp().run()


def main():
    client = AgentClient()
    if OS_TYPE == "DARWIN":
        run_rumps(client)
    else:
        run_pystray(client)


if __name__ == "__main__":
    main()
