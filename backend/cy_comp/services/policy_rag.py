"""
cy_comp/services/policy_rag.py
================================
CyMind RAG HTTP client for policy document management.

Reads CYMIND_API_URL and CYMIND_ADMIN_KEY from ai_settings.json.
Sub-collection naming: policy-{framework}  e.g. policy-iso27001, policy-dora

Methods:
  create_collection(framework)
  list_collections()
  upload_document(collection_id, file_storage, metadata)
  list_documents(collection_id)
  delete_document(doc_id)
  reindex_collection(collection_id)
  get_admin_key() -> str
"""

import json
import logging
import uuid
from pathlib import Path
from typing import Optional

import requests

from cy_comp.models import db
from core.config import AI_SETTINGS_FILE

log = logging.getLogger("cycentra.cy_comp.policy_rag")

_CYMIND_DEFAULT_URL = "http://127.0.0.1:8200"


def _load_cymind_settings() -> dict:
    """Load ai_settings.json and return relevant CyMind fields."""
    try:
        if AI_SETTINGS_FILE.exists():
            raw = json.loads(AI_SETTINGS_FILE.read_text())
            return raw
    except Exception as exc:
        log.warning("_load_cymind_settings: %s", exc)
    return {}


def _cymind_integration(settings: dict) -> dict:
    """Return the cymind_integration sub-object written by Platform Extensions."""
    return settings.get("cymind_integration", {})


def get_cymind_url() -> str:
    settings = _load_cymind_settings()
    ci = _cymind_integration(settings)
    return (
        ci.get("cymindUrl")
        or settings.get("fields", {}).get("baseUrl")
        or settings.get("cymind_url")
        or settings.get("CYMIND_API_URL")
        or _CYMIND_DEFAULT_URL
    )


def get_cymind_api_key() -> str:
    """
    Return the best available CyMind API key for RAG operations.
    Priority: explicit cymind_admin_key (set in GRC Settings) →
              M2M service key (cymk_…) → chat key (pak_…).
    """
    settings = _load_cymind_settings()
    ci = _cymind_integration(settings)
    return (
        settings.get("cymind_admin_key")   # admin key set explicitly in GRC Settings
        or ci.get("apiKey")                # M2M service-to-service key
        or ci.get("chatApiKey")            # chat/user key fallback
        or ""
    )


def _headers() -> dict:
    key = get_cymind_api_key()
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def _collection_name(framework: str) -> str:
    """Normalize framework to collection name: policy-iso27001, policy-dora, etc."""
    slug = framework.lower().replace(" ", "").replace("_", "").replace("-", "")
    return f"policy-{slug}"


# ── Collection management ─────────────────────────────────────────────────────

def list_collections() -> list[dict]:
    """
    Return all CyMind collections whose name starts with 'policy-'.
    Falls back to listing from cy_comp_policy_docs if CyMind is unreachable.
    """
    try:
        resp = requests.get(
            f"{get_cymind_url()}/api/collections",
            headers=_headers(),
            timeout=8,
        )
        if resp.ok:
            all_cols = resp.json() if isinstance(resp.json(), list) else resp.json().get("collections", [])
            return [c for c in all_cols if str(c.get("name", "")).startswith("policy-")]
    except Exception as exc:
        log.warning("list_collections: CyMind unreachable (%s) — reading local DB", exc)

    # Fallback: distinct collection_ids from local metadata table
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT collection_id, framework, COUNT(*) AS doc_count
                FROM cy_comp_policy_docs
                GROUP BY collection_id, framework
                ORDER BY collection_id;
                """
            )
            for cid, fw, cnt in cur.fetchall():
                rows.append({"id": cid, "name": cid, "framework": fw, "doc_count": cnt})
    except Exception as exc:
        log.error("list_collections fallback DB: %s", exc)
    return rows


def create_collection(framework: str) -> dict:
    """
    Create a new policy-{framework} collection in CyMind RAG.
    Returns {collection_id, name, framework}.
    """
    name = _collection_name(framework)
    result = {"id": name, "name": name, "framework": framework}

    try:
        resp = requests.post(
            f"{get_cymind_url()}/api/collections",
            headers=_headers(),
            json={"name": name, "description": f"Policy documents for {framework}"},
            timeout=8,
        )
        if resp.ok:
            data = resp.json()
            result["id"] = data.get("id") or data.get("collection_id") or name
    except Exception as exc:
        log.error("create_collection(%s): %s", framework, exc)

    return result


def upload_document(collection_id: str, file_storage, metadata: dict, uploaded_by: str) -> dict:
    """
    Upload a document to a CyMind collection.
    file_storage: Werkzeug FileStorage object from Flask request.files.

    Returns the created policy_doc metadata dict.
    """
    doc_id   = str(uuid.uuid4())
    filename = file_storage.filename or "document"
    fw       = metadata.get("framework") or collection_id.replace("policy-", "")

    cymind_doc_id = None
    try:
        files = {"file": (filename, file_storage.stream, file_storage.content_type or "application/octet-stream")}
        data  = {
            "collection_id": collection_id,
            "metadata":      json.dumps({"framework": fw, "doc_id": doc_id}),
        }
        key = get_admin_key()
        auth_header = {"Authorization": f"Bearer {key}"} if key else {}
        resp = requests.post(
            f"{get_cymind_url()}/api/documents",
            headers=auth_header,
            files=files,
            data=data,
            timeout=30,
        )
        if resp.ok:
            rd          = resp.json()
            cymind_doc_id = rd.get("doc_id") or rd.get("id")
    except Exception as exc:
        log.error("upload_document: CyMind upload failed: %s", exc)

    # Save metadata to local DB
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_policy_docs
                    (id, name, file_type, collection_id, cymind_doc_id,
                     framework, indexed, uploaded_by, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW());
                """,
                (
                    doc_id, filename,
                    filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin",
                    collection_id, cymind_doc_id, fw,
                    bool(cymind_doc_id),
                    uploaded_by,
                )
            )
    except Exception as exc:
        log.error("upload_document DB persist: %s", exc)

    return {
        "id":            doc_id,
        "name":          filename,
        "collection_id": collection_id,
        "cymind_doc_id": cymind_doc_id,
        "framework":     fw,
        "indexed":       bool(cymind_doc_id),
        "uploaded_by":   uploaded_by,
    }


def list_documents(collection_id: str) -> list[dict]:
    """Return documents for a collection (from local metadata + CyMind index status)."""
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, file_type, collection_id, cymind_doc_id,
                       framework, indexed, uploaded_by, created_at
                FROM cy_comp_policy_docs
                WHERE collection_id = %s
                ORDER BY created_at DESC;
                """,
                (collection_id,)
            )
            for r in cur.fetchall():
                rows.append({
                    "id":            r[0],
                    "name":          r[1],
                    "file_type":     r[2],
                    "collection_id": r[3],
                    "cymind_doc_id": r[4],
                    "framework":     r[5],
                    "indexed":       r[6],
                    "uploaded_by":   r[7],
                    "created_at":    r[8].isoformat() if r[8] else None,
                })
    except Exception as exc:
        log.error("list_documents(%s): %s", collection_id, exc)
    return rows


def delete_document(doc_id: str) -> bool:
    """Delete a document from CyMind and local metadata."""
    cymind_doc_id = None
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT cymind_doc_id FROM cy_comp_policy_docs WHERE id = %s;",
                (doc_id,)
            )
            row = cur.fetchone()
            if row:
                cymind_doc_id = row[0]
    except Exception as exc:
        log.error("delete_document lookup: %s", exc)

    # Remove from CyMind
    if cymind_doc_id:
        try:
            requests.delete(
                f"{get_cymind_url()}/api/documents/{cymind_doc_id}",
                headers=_headers(),
                timeout=8,
            )
        except Exception as exc:
            log.warning("delete_document CyMind delete: %s", exc)

    # Remove from local metadata
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_policy_docs WHERE id = %s;", (doc_id,))
            return cur.rowcount > 0
    except Exception as exc:
        log.error("delete_document DB: %s", exc)
        return False


def reindex_collection(collection_id: str) -> dict:
    """Trigger CyMind re-indexing for a collection. Returns status."""
    try:
        resp = requests.post(
            f"{get_cymind_url()}/api/collections/{collection_id}/reindex",
            headers=_headers(),
            timeout=30,
        )
        if resp.ok:
            return {"status": "reindexing", "collection_id": collection_id}
        return {"status": "error", "detail": resp.text[:200]}
    except Exception as exc:
        log.error("reindex_collection(%s): %s", collection_id, exc)
        return {"status": "error", "detail": str(exc)}
