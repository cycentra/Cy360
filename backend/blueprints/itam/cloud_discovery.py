"""
blueprints/itam/cloud_discovery.py
====================================
Cloud asset discovery — AWS EC2 and Azure VMs.
Maps cloud instances directly to the network_assets table
with discovery_source='aws' or 'azure'.

Requires:
  - AWS:   boto3 (pip install boto3)
  - Azure: azure-mgmt-compute + azure-mgmt-network (pip install azure-mgmt-compute azure-mgmt-network azure-identity)

Both are guarded with ImportError — missing one doesn't break the other.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ── AWS EC2 Discovery ───────────────────────────────────────────────────────

def _ec2_instance_to_asset(instance: dict) -> dict | None:
    """Map a boto3 EC2 instance dict to a network_assets row dict."""
    private_ip = instance.get("PrivateIpAddress", "")
    if not private_ip:
        return None

    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    name = tags.get("Name", "") or tags.get("name", "")
    env  = tags.get("Environment", tags.get("Env", ""))
    team = tags.get("Team", tags.get("Owner", ""))

    itype = instance.get("InstanceType", "")
    state = instance.get("State", {}).get("Name", "")
    az    = instance.get("Placement", {}).get("AvailabilityZone", "")
    image = instance.get("ImageId", "")
    vpc   = instance.get("VpcId", "")
    pub_ip = instance.get("PublicIpAddress", "")

    # Infer asset type from instance type prefix
    asset_type = "server"
    if itype.startswith("t") or itype.startswith("m"):
        asset_type = "server"

    notes_parts = [f"AWS {itype}"]
    if az:      notes_parts.append(f"AZ:{az}")
    if env:     notes_parts.append(f"Env:{env}")
    if team:    notes_parts.append(f"Team:{team}")
    if vpc:     notes_parts.append(f"VPC:{vpc}")
    if pub_ip:  notes_parts.append(f"PublicIP:{pub_ip}")

    tags_list = [f"{k}={v}" for k, v in tags.items() if k not in ("Name", "name")]

    return {
        "ip_address":       private_ip,
        "hostname":         name or instance.get("InstanceId", ""),
        "mac_address":      None,
        "asset_type":       asset_type,
        "vendor":           "Amazon Web Services",
        "os_info":          json.dumps({"image_id": image, "instance_type": itype, "state": state}),
        "notes":            " | ".join(notes_parts),
        "tags":             tags_list[:10],
        "discovery_source": "aws",
        "is_managed":       False,
    }


def sync_aws_assets(conn, regions: list[str], access_key: str, secret_key: str,
                    session_token: str = "") -> dict:
    """
    Discover all running EC2 instances across the given regions.
    Upserts into network_assets with discovery_source='aws'.
    Returns {upserted: N, regions_scanned: N, errors: [...]}
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return {"error": "boto3 not installed — run: pip install boto3", "upserted": 0}

    total  = 0
    errors = []

    for region in regions:
        try:
            session_kwargs: dict = {
                "aws_access_key_id":     access_key,
                "aws_secret_access_key": secret_key,
                "region_name":           region,
            }
            if session_token:
                session_kwargs["aws_session_token"] = session_token

            ec2 = boto3.client("ec2", **session_kwargs)

            paginator = ec2.get_paginator("describe_instances")
            pages     = paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            )

            with conn.cursor() as cur:
                for page in pages:
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            asset = _ec2_instance_to_asset(instance)
                            if not asset:
                                continue
                            cur.execute("""
                                INSERT INTO network_assets
                                    (ip_address, hostname, mac_address, asset_type, vendor,
                                     os_info, notes, tags, discovery_source, is_managed, last_seen)
                                VALUES (%s::inet, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                                ON CONFLICT (ip_address) DO UPDATE SET
                                    hostname         = COALESCE(NULLIF(EXCLUDED.hostname,''), network_assets.hostname),
                                    vendor           = CASE WHEN network_assets.discovery_source='cmdb' THEN network_assets.vendor ELSE EXCLUDED.vendor END,
                                    notes            = CASE WHEN network_assets.discovery_source='cmdb' THEN network_assets.notes ELSE EXCLUDED.notes END,
                                    tags             = CASE WHEN network_assets.discovery_source='cmdb' THEN network_assets.tags ELSE EXCLUDED.tags END,
                                    discovery_source = CASE WHEN network_assets.discovery_source='cmdb' THEN 'cmdb' ELSE EXCLUDED.discovery_source END,
                                    last_seen        = NOW()
                            """, [
                                asset["ip_address"], asset["hostname"], asset["mac_address"],
                                asset["asset_type"], asset["vendor"], asset["os_info"],
                                asset["notes"], asset["tags"], asset["discovery_source"],
                                asset["is_managed"],
                            ])
                            total += 1
            conn.commit()
            log.info("[CLOUD] AWS %s: %d instances synced", region, total)

        except (BotoCoreError, ClientError) as e:
            errors.append(f"AWS {region}: {e}")
            log.warning("[CLOUD] AWS %s error: %s", region, e)
        except Exception as e:
            errors.append(f"AWS {region}: {e}")
            log.warning("[CLOUD] AWS %s unexpected error: %s", region, e)

    return {"upserted": total, "regions_scanned": len(regions), "errors": errors}


# ── Azure VM Discovery ──────────────────────────────────────────────────────

def _azure_vm_to_asset(vm, private_ip: str, public_ip: str) -> dict | None:
    if not private_ip:
        return None

    tags = vm.tags or {}
    name = vm.name or ""
    loc  = vm.location or ""
    size = ""
    try:
        size = vm.hardware_profile.vm_size or ""
    except Exception:
        pass

    notes_parts = [f"Azure {size}"]
    if loc:
        notes_parts.append(f"Region:{loc}")
    if public_ip:
        notes_parts.append(f"PublicIP:{public_ip}")

    tags_list = [f"{k}={v}" for k, v in list(tags.items())[:10]]

    return {
        "ip_address":       private_ip,
        "hostname":         name,
        "mac_address":      None,
        "asset_type":       "server",
        "vendor":           "Microsoft Azure",
        "os_info":          json.dumps({"vm_size": size, "location": loc}),
        "notes":            " | ".join(notes_parts),
        "tags":             tags_list,
        "discovery_source": "azure",
        "is_managed":       False,
    }


def sync_azure_assets(conn, subscription_id: str, client_id: str,
                      client_secret: str, tenant_id: str) -> dict:
    """
    Discover all Azure VMs in the subscription.
    Requires: azure-mgmt-compute, azure-mgmt-network, azure-identity
    """
    try:
        from azure.identity import ClientSecretCredential          # type: ignore
        from azure.mgmt.compute import ComputeManagementClient     # type: ignore
        from azure.mgmt.network import NetworkManagementClient     # type: ignore
    except ImportError:
        return {"error": "azure packages not installed — run: pip install azure-mgmt-compute azure-mgmt-network azure-identity", "upserted": 0}

    try:
        credential = ClientSecretCredential(
            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
        )
        compute = ComputeManagementClient(credential, subscription_id)
        network = NetworkManagementClient(credential, subscription_id)

        total = 0
        with conn.cursor() as cur:
            for vm in compute.virtual_machines.list_all():
                private_ip = ""
                public_ip  = ""
                try:
                    rg = vm.id.split("/resourceGroups/")[1].split("/")[0]
                    nics = vm.network_profile.network_interfaces or []
                    for nic_ref in nics:
                        nic_name = nic_ref.id.split("/")[-1]
                        nic = network.network_interfaces.get(rg, nic_name)
                        for ipc in nic.ip_configurations or []:
                            if ipc.private_ip_address and not private_ip:
                                private_ip = ipc.private_ip_address
                            if ipc.public_ip_address and not public_ip:
                                pip_name = ipc.public_ip_address.id.split("/")[-1]
                                pip = network.public_ip_addresses.get(rg, pip_name)
                                public_ip = pip.ip_address or ""
                except Exception:
                    pass

                asset = _azure_vm_to_asset(vm, private_ip, public_ip)
                if not asset:
                    continue

                cur.execute("""
                    INSERT INTO network_assets
                        (ip_address, hostname, asset_type, vendor, os_info, notes, tags, discovery_source, is_managed, last_seen)
                    VALUES (%s::inet, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (ip_address) DO UPDATE SET
                        hostname         = COALESCE(NULLIF(EXCLUDED.hostname,''), network_assets.hostname),
                        vendor           = CASE WHEN network_assets.discovery_source='cmdb' THEN network_assets.vendor ELSE EXCLUDED.vendor END,
                        discovery_source = CASE WHEN network_assets.discovery_source='cmdb' THEN 'cmdb' ELSE EXCLUDED.discovery_source END,
                        last_seen        = NOW()
                """, [
                    asset["ip_address"], asset["hostname"], asset["asset_type"], asset["vendor"],
                    asset["os_info"], asset["notes"], asset["tags"],
                    asset["discovery_source"], asset["is_managed"],
                ])
                total += 1

        conn.commit()
        log.info("[CLOUD] Azure: %d VMs synced", total)
        return {"upserted": total, "regions_scanned": 1, "errors": []}

    except Exception as e:
        log.warning("[CLOUD] Azure sync error: %s", e)
        return {"error": str(e), "upserted": 0}
