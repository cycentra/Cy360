"""
cysiemstack/connectors/registry.py
=====================================
Vendor string → connector class. Single source of truth — both
blueprints/connectors/routes.py (test-connection, manual pull) and the
scheduler polling job (blueprints/connectors/routes.py
register_connector_scheduler) import from here.
"""
from __future__ import annotations
from typing import Any

from .base import BaseConnector
from .wazuh_connector import WazuhConnector
from .splunk_connector import SplunkConnector
from .qradar_connector import QRadarConnector
from .sentinelone_connector import SentinelOneConnector
from .paloalto_connector import PaloAltoConnector
from .office365_connector import Office365Connector
from .azure_connector import AzureConnector
from .aws_connector import AWSConnector
from .gcp_connector import GCPConnector

CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = {
    "wazuh":       WazuhConnector,
    "splunk":      SplunkConnector,
    "qradar":      QRadarConnector,
    "sentinelone": SentinelOneConnector,
    "paloalto":    PaloAltoConnector,
    "office365":   Office365Connector,
    "azure":       AzureConnector,
    "aws":         AWSConnector,
    "gcp":         GCPConnector,
}


def build_connector(vendor: str, config: dict[str, Any]) -> BaseConnector:
    cls = CONNECTOR_REGISTRY.get(vendor)
    if cls is None:
        raise ValueError(f"Unknown connector vendor: {vendor!r} (known: {sorted(CONNECTOR_REGISTRY)})")
    return cls(config)
