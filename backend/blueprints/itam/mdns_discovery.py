"""
blueprints/itam/mdns_discovery.py
====================================
Passive mDNS/DNS-SD listener that discovers LAN devices without active scanning.
Uses the zeroconf library.
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable

log = logging.getLogger(__name__)

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False

MDNS_SERVICES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_ftp._tcp.local.",
    "_hap._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_raop._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_nvstream_dbd._tcp.local.",
    "_axis-video._tcp.local.",
    "_daap._tcp.local.",
]

SERVICE_TO_ASSET_TYPE: dict[str, str] = {
    "_printer._tcp.local.": "printer",
    "_ipp._tcp.local.": "printer",
    "_ipps._tcp.local.": "printer",
    "_pdl-datastream._tcp.local.": "printer",
    "_scanner._tcp.local.": "printer",
    "_ssh._tcp.local.": "server",
    "_smb._tcp.local.": "server",
    "_http._tcp.local.": "server",
    "_https._tcp.local.": "server",
    "_hap._tcp.local.": "iot_device",
    "_airplay._tcp.local.": "iot_device",
    "_googlecast._tcp.local.": "iot_device",
    "_spotify-connect._tcp.local.": "iot_device",
    "_axis-video._tcp.local.": "camera",
}


class _MdnsListener:
    """Internal zeroconf ServiceListener that feeds discovered devices to the parent service."""

    def __init__(self, service: "MdnsDiscoveryService") -> None:
        self._service = service

    def add_service(self, zc: "Zeroconf", service_type: str, name: str) -> None:
        try:
            info = zc.get_service_info(service_type, name)
            if info is None:
                return
            ip = None
            for addr_bytes in info.addresses:
                if len(addr_bytes) == 4:
                    try:
                        ip = socket.inet_ntoa(addr_bytes)
                        break
                    except OSError:
                        continue
            if ip is None:
                return
            hostname = info.server or name
            if hostname.endswith("."):
                hostname = hostname[:-1]
            properties: dict = {}
            if info.properties:
                for k, v in info.properties.items():
                    try:
                        key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8") if isinstance(v, bytes) else str(v) if v is not None else ""
                        properties[key] = val
                    except Exception:
                        pass
            device = {
                "ip": ip,
                "hostname": hostname,
                "service_type": service_type,
                "port": info.port,
                "properties": properties,
                "asset_type": SERVICE_TO_ASSET_TYPE.get(service_type, "unknown"),
            }
            self._service._on_found(device)
        except Exception as exc:
            log.debug("mdns add_service error for %s/%s: %s", service_type, name, exc)

    def remove_service(self, zc: "Zeroconf", service_type: str, name: str) -> None:
        pass

    def update_service(self, zc: "Zeroconf", service_type: str, name: str) -> None:
        self.add_service(zc, service_type, name)


class MdnsDiscoveryService:
    """Passive mDNS listener that browses all known service types on the local LAN."""

    def __init__(self, on_device_found: Callable[[dict], None]) -> None:
        self._callback = on_device_found
        self._zc: "Zeroconf | None" = None
        self._browsers: list = []
        self._seen_ips: set[str] = set()
        self._devices: list[dict] = []
        self._lock = threading.Lock()

    def _on_found(self, device: dict) -> None:
        ip = device["ip"]
        with self._lock:
            already_seen = ip in self._seen_ips
            if not already_seen:
                self._seen_ips.add(ip)
                self._devices.append(device)
        if not already_seen:
            try:
                self._callback(device)
            except Exception as exc:
                log.warning("mdns on_device_found callback raised: %s", exc)

    def start(self) -> bool:
        """Start listening. Returns False if zeroconf is not installed."""
        if not _ZEROCONF_AVAILABLE:
            log.warning("zeroconf not installed; mDNS discovery unavailable")
            return False
        try:
            self._zc = Zeroconf()
            listener = _MdnsListener(self)
            for service_type in MDNS_SERVICES:
                try:
                    browser = ServiceBrowser(self._zc, service_type, listener)
                    self._browsers.append(browser)
                except Exception as exc:
                    log.debug("Failed to browse %s: %s", service_type, exc)
            log.info("mDNS discovery started; browsing %d service types", len(self._browsers))
            return True
        except Exception as exc:
            log.error("mDNS discovery failed to start: %s", exc)
            return False

    def stop(self) -> None:
        """Stop the mDNS listener and release resources."""
        if self._zc is not None:
            try:
                self._zc.close()
            except Exception as exc:
                log.debug("mDNS zeroconf close error: %s", exc)
            self._zc = None
        self._browsers.clear()
        log.info("mDNS discovery stopped")

    def get_discovered(self) -> list[dict]:
        """Return a snapshot copy of all discovered devices."""
        with self._lock:
            return list(self._devices)


_service_instance: MdnsDiscoveryService | None = None


def start_mdns_discovery(on_device_found: Callable[[dict], None]) -> bool:
    """Start the global singleton mDNS listener."""
    global _service_instance
    if _service_instance is not None:
        log.warning("mDNS discovery already running; ignoring start request")
        return True
    _service_instance = MdnsDiscoveryService(on_device_found)
    return _service_instance.start()


def stop_mdns_discovery() -> None:
    """Stop the global singleton mDNS listener."""
    global _service_instance
    if _service_instance is not None:
        _service_instance.stop()
        _service_instance = None
