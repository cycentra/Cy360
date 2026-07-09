"""
cy_comp/services/policy_rag.py
================================
CyMind RAG HTTP client for policy document management.

Reads CYMIND_API_URL and API key from ai_settings.json (cymind_integration{} object).
Sub-collection naming: policy-{framework}  e.g. policy-iso27001, policy-dora

CyMind RAG API base: /api/v1/rag/
  GET  /api/v1/rag/collections                         → list collections
  POST /api/v1/rag/collections?name=&scope=&color=     → create collection
  GET  /api/v1/rag/collections/{id}/documents          → list documents
  POST /api/v1/rag/collections/{id}/upload             → upload document (multipart)
  DEL  /api/v1/rag/documents/{doc_id}                  → delete document
  GET  /api/v1/rag/query/multi?collections=&query=     → multi-collection RAG query
"""

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

import requests

from cy_comp.models import db
from core.config import AI_SETTINGS_FILE

log = logging.getLogger("cycentra.cy_comp.policy_rag")

_CYMIND_DEFAULT_URL = "http://127.0.0.1:8200"


def _load_cymind_settings() -> dict:
    try:
        if AI_SETTINGS_FILE.exists():
            return json.loads(AI_SETTINGS_FILE.read_text())
    except Exception as exc:
        log.warning("_load_cymind_settings: %s", exc)
    return {}


def _cymind_integration(settings: dict) -> dict:
    return settings.get("cymind_integration", {})


def get_cymind_url() -> str:
    settings = _load_cymind_settings()
    ci = _cymind_integration(settings)
    return (
        os.environ.get("CYMIND_API_URL")
        or ci.get("cymindUrl")
        or settings.get("fields", {}).get("baseUrl")
        or settings.get("cymind_url")
        or settings.get("CYMIND_API_URL")
        or _CYMIND_DEFAULT_URL
    )


def get_cymind_api_key() -> str:
    """
    Priority: vault env → explicit cymind_admin_key → chat pak_ key (CyM_) → M2M cymk_ key.
    Chat PAK key is preferred over admin key because /api/v1/chat requires a CyM_ token.
    """
    settings = _load_cymind_settings()
    ci = _cymind_integration(settings)
    return (
        os.environ.get("CYMIND_API_KEY")
        or settings.get("cymind_admin_key")
        or ci.get("chatApiKey")
        or ci.get("apiKey")
        or ""
    )


def _headers() -> dict:
    key = get_cymind_api_key()
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def _auth_header() -> dict:
    """Auth-only header (no Content-Type) for multipart file uploads."""
    key = get_cymind_api_key()
    return {"Authorization": f"Bearer {key}"} if key else {}


def _rag_url(path: str) -> str:
    """Build full CyMind RAG API URL."""
    return f"{get_cymind_url()}/api/v1/rag/{path.lstrip('/')}"


def _collection_name(framework: str) -> str:
    slug = framework.lower().replace(" ", "").replace("_", "").replace("-", "")
    return f"policy-{slug}"


def _cymind_collection_id(collection_id: str) -> str:
    """Resolve a logical collection name (e.g. 'org-policies') to the CyMind ID
    ('policy-orgpolicies'). Already-prefixed IDs pass through unchanged."""
    if collection_id.startswith("policy-") or collection_id.startswith("framework-"):
        return collection_id
    return _collection_name(collection_id)


def _framework_collection_name(framework: str) -> str:
    """RAG collection name for framework reference docs: framework-{slug}."""
    slug = framework.lower().replace(" ", "").replace("_", "").replace("-", "")
    return f"framework-{slug}"


SUPPORTED_FRAMEWORKS = [
    {"id": "iso27001", "label": "ISO/IEC 27001",  "color": "#00e5a0"},
    {"id": "nis2",     "label": "NIS2",            "color": "#4d9eff"},
    {"id": "dora",     "label": "DORA",            "color": "#b06eff"},
    {"id": "soc2",     "label": "SOC 2 Type II",   "color": "#ff8c00"},
    {"id": "nist_csf", "label": "NIST CSF 2.0",   "color": "#6378ff"},
    {"id": "pci_dss",  "label": "PCI DSS 4.0",    "color": "#ff3b3b"},
]


# ── Collection management ─────────────────────────────────────────────────────

def list_collections() -> list[dict]:
    """
    Return all CyMind collections whose name starts with 'policy-'.
    Falls back to local cy_comp_policy_docs metadata if CyMind unreachable.
    """
    try:
        resp = requests.get(_rag_url("collections"), headers=_headers(), timeout=8)
        if resp.ok:
            data = resp.json()
            all_cols = data.get("collections", data) if isinstance(data, dict) else data
            return [c for c in all_cols if str(c.get("name", "")).startswith("policy-")]
    except Exception as exc:
        log.warning("list_collections: CyMind unreachable (%s) — reading local DB", exc)

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
                rows.append({"id": cid, "name": cid, "framework": fw, "file_count": cnt})
    except Exception as exc:
        log.error("list_collections fallback DB: %s", exc)
    return rows


def create_collection(framework: str) -> dict:
    """Create policy-{framework} collection in CyMind."""
    name = _collection_name(framework)
    result = {"id": name, "name": name, "framework": framework}
    try:
        resp = requests.post(
            _rag_url("collections"),
            headers=_auth_header(),
            params={"name": name, "scope": "all", "color": "#00D9FF"},
            timeout=8,
        )
        if resp.ok:
            data = resp.json()
            result["id"] = data.get("id") or name
        elif resp.status_code == 400:
            # Collection already exists — treat as success
            log.info("create_collection(%s): already exists", name)
        else:
            log.warning("create_collection(%s): CyMind returned %s %s", name, resp.status_code, resp.text[:200])
    except Exception as exc:
        log.error("create_collection(%s): %s", framework, exc)
    return result


def upload_document(collection_id: str, file_storage, metadata: dict, uploaded_by: str) -> dict:
    """
    Upload a document to a CyMind RAG collection.
    file_storage: Werkzeug FileStorage object from Flask request.files.
    metadata may contain: framework, tag
    """
    doc_id    = str(uuid.uuid4())
    filename  = file_storage.filename or "document"
    fw        = metadata.get("framework") or collection_id.replace("policy-", "")
    tag       = metadata.get("tag") or None
    file_size = None

    # Resolve logical names (e.g. "org-policies") to CyMind IDs ("policy-orgpolicies")
    cymind_id = _cymind_collection_id(collection_id)

    cymind_doc_id = None
    try:
        file_bytes = file_storage.read()
        file_size  = len(file_bytes)
        file_storage.seek(0)
        files = {
            "file": (filename, file_bytes, file_storage.content_type or "application/octet-stream")
        }
        resp = requests.post(
            _rag_url(f"collections/{cymind_id}/upload"),
            headers=_auth_header(),
            files=files,
            params={"chunk_size": 512, "overlap": 64},
            timeout=60,
        )
        if resp.ok:
            rd = resp.json()
            cymind_doc_id = rd.get("doc_id") or rd.get("id")
            log.info("upload_document: CyMind accepted %s → doc_id=%s", filename, cymind_doc_id)
        else:
            log.warning("upload_document: CyMind %s %s", resp.status_code, resp.text[:300])
    except Exception as exc:
        log.error("upload_document: CyMind upload failed: %s", exc)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_policy_docs
                    (id, name, file_type, collection_id, cymind_doc_id,
                     framework, indexed, uploaded_by, doc_type, tag, file_size, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'policy',%s,%s,NOW(),NOW());
                """,
                (
                    doc_id, filename,
                    filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin",
                    collection_id, cymind_doc_id, fw,
                    bool(cymind_doc_id),
                    uploaded_by, tag, file_size,
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
        "tag":           tag,
        "file_size":     file_size,
        "indexed":       bool(cymind_doc_id),
        "uploaded_by":   uploaded_by,
        "doc_type":      "policy",
    }


def save_text_as_document(collection_id: str, text: str, filename: str,
                          metadata: dict, uploaded_by: str) -> dict:
    """
    Save a raw text string as a policy document in a RAG collection.
    Used by the AI Policy Creation → Save to Library flow.
    """
    doc_id     = str(uuid.uuid4())
    fw         = metadata.get("framework") or collection_id.replace("policy-", "")
    tag        = metadata.get("tag") or "security"
    file_bytes = text.encode("utf-8")
    file_size  = len(file_bytes)
    cymind_id  = _cymind_collection_id(collection_id)
    cymind_doc_id = None

    try:
        resp = requests.post(
            _rag_url(f"collections/{cymind_id}/upload"),
            headers=_auth_header(),
            files={"file": (filename, file_bytes, "text/plain")},
            params={"chunk_size": 512, "overlap": 64},
            timeout=60,
        )
        if resp.ok:
            rd = resp.json()
            cymind_doc_id = rd.get("doc_id") or rd.get("id")
            log.info("save_text_as_document: CyMind accepted %s → doc_id=%s", filename, cymind_doc_id)
        else:
            log.warning("save_text_as_document: CyMind %s %s", resp.status_code, resp.text[:300])
    except Exception as exc:
        log.error("save_text_as_document: CyMind upload failed: %s", exc)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_policy_docs
                    (id, name, file_type, collection_id, cymind_doc_id,
                     framework, indexed, uploaded_by, doc_type, tag, file_size, created_at, updated_at)
                VALUES (%s,%s,'txt',%s,%s,%s,%s,%s,'policy',%s,%s,NOW(),NOW());
                """,
                (
                    doc_id, filename, collection_id, cymind_doc_id, fw,
                    bool(cymind_doc_id), uploaded_by, tag, file_size,
                )
            )
    except Exception as exc:
        log.error("save_text_as_document DB persist: %s", exc)

    return {
        "id":            doc_id,
        "name":          filename,
        "collection_id": collection_id,
        "cymind_doc_id": cymind_doc_id,
        "framework":     fw,
        "tag":           tag,
        "file_size":     file_size,
        "indexed":       bool(cymind_doc_id),
        "uploaded_by":   uploaded_by,
        "doc_type":      "policy",
    }


def list_documents(collection_id: str) -> list[dict]:
    """Return policy documents (doc_type='policy') for a collection from local metadata."""
    rows = []
    cymind_id = _cymind_collection_id(collection_id)
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, file_type, collection_id, cymind_doc_id,
                       framework, indexed, uploaded_by, tag, file_size, created_at
                FROM cy_comp_policy_docs
                WHERE collection_id = ANY(%s::text[])
                  AND COALESCE(doc_type, 'policy') = 'policy'
                ORDER BY created_at DESC;
                """,
                ([collection_id, cymind_id],)
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
                    "tag":           r[8],
                    "file_size":     r[9],
                    "created_at":    r[10].isoformat() if r[10] else None,
                })
    except Exception as exc:
        log.error("list_documents(%s): %s", collection_id, exc)
    return rows


def delete_document(doc_id: str) -> bool:
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

    if cymind_doc_id:
        try:
            requests.delete(
                _rag_url(f"documents/{cymind_doc_id}"),
                headers=_auth_header(),
                timeout=8,
            )
        except Exception as exc:
            log.warning("delete_document CyMind: %s", exc)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_policy_docs WHERE id = %s;", (doc_id,))
            return cur.rowcount > 0
    except Exception as exc:
        log.error("delete_document DB: %s", exc)
        return False


def reindex_collection(collection_id: str) -> dict:
    """
    Ask CyMind to reindex all documents in a collection.
    Resolves logical names to CyMind IDs (e.g. 'org-policies' → 'policy-orgpolicies').
    """
    cymind_id = _cymind_collection_id(collection_id)
    try:
        resp = requests.post(
            _rag_url(f"collections/{cymind_id}/reindex"),
            headers=_auth_header(),
            timeout=30,
        )
        if resp.ok:
            return resp.json()
        log.warning("reindex_collection(%s): CyMind %s %s", cymind_id, resp.status_code, resp.text[:200])
        return {"status": "error", "message": f"CyMind returned {resp.status_code}"}
    except Exception as exc:
        log.error("reindex_collection(%s): %s", cymind_id, exc)
        return {"status": "error", "message": str(exc)}


# ── Framework Document Management (admin — System Settings) ───────────────────

def ensure_framework_collections() -> list[dict]:
    """
    Ensure all supported frameworks have a CyMind RAG collection (framework-{id}).
    Returns list of {id, label, color, collection_id, doc_count, doc_locked_count}.
    """
    result = []
    for fw in SUPPORTED_FRAMEWORKS:
        col_id = _framework_collection_name(fw["id"])
        try:
            requests.post(
                _rag_url("collections"),
                headers=_auth_header(),
                params={"name": col_id, "scope": "all", "color": fw["color"]},
                timeout=8,
            )
        except Exception as exc:
            log.debug("ensure_framework_collections(%s): %s", col_id, exc)

        doc_count = 0
        locked_count = 0
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT COUNT(*), COUNT(*) FILTER (WHERE locked) "
                    "FROM cy_comp_policy_docs WHERE collection_id = %s AND doc_type = 'framework';",
                    (col_id,)
                )
                row = cur.fetchone()
                if row:
                    doc_count, locked_count = row[0] or 0, row[1] or 0
        except Exception as exc:
            log.error("ensure_framework_collections count(%s): %s", col_id, exc)

        result.append({
            **fw,
            "collection_id": col_id,
            "doc_count": doc_count,
            "locked_count": locked_count,
        })
    return result


def upload_framework_doc(framework: str, file_storage, locked: bool, uploaded_by: str) -> dict:
    """Upload a reference document to a framework's RAG collection."""
    col_id   = _framework_collection_name(framework)
    doc_id   = str(uuid.uuid4())
    filename = file_storage.filename or "document"
    file_size = None

    cymind_doc_id = None
    try:
        file_bytes = file_storage.read()
        file_size  = len(file_bytes)
        file_storage.seek(0)
        files = {"file": (filename, file_bytes, file_storage.content_type or "application/octet-stream")}
        resp = requests.post(
            _rag_url(f"collections/{col_id}/upload"),
            headers=_auth_header(),
            files=files,
            params={"chunk_size": 512, "overlap": 64},
            timeout=60,
        )
        if resp.ok:
            rd = resp.json()
            cymind_doc_id = rd.get("doc_id") or rd.get("id")
        else:
            log.warning("upload_framework_doc: CyMind %s %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        log.error("upload_framework_doc CyMind: %s", exc)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_policy_docs
                    (id, name, file_type, collection_id, cymind_doc_id,
                     framework, indexed, uploaded_by, doc_type, locked, file_size, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'framework',%s,%s,NOW(),NOW());
                """,
                (
                    doc_id, filename,
                    filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin",
                    col_id, cymind_doc_id, framework,
                    bool(cymind_doc_id), uploaded_by, locked, file_size,
                )
            )
    except Exception as exc:
        log.error("upload_framework_doc DB: %s", exc)

    return {
        "id": doc_id, "name": filename, "collection_id": col_id,
        "cymind_doc_id": cymind_doc_id, "framework": framework,
        "indexed": bool(cymind_doc_id), "locked": locked,
        "file_size": file_size, "uploaded_by": uploaded_by, "doc_type": "framework",
    }


def list_framework_docs(framework: str) -> list[dict]:
    """List framework reference documents (doc_type='framework')."""
    col_id = _framework_collection_name(framework)
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, file_type, cymind_doc_id, framework,
                       indexed, locked, file_size, uploaded_by, created_at
                FROM cy_comp_policy_docs
                WHERE collection_id = %s AND doc_type = 'framework'
                ORDER BY created_at DESC;
                """,
                (col_id,)
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0], "name": r[1], "file_type": r[2], "cymind_doc_id": r[3],
                    "framework": r[4], "indexed": r[5], "locked": r[6],
                    "file_size": r[7], "uploaded_by": r[8],
                    "created_at": r[9].isoformat() if r[9] else None,
                })
    except Exception as exc:
        log.error("list_framework_docs(%s): %s", framework, exc)
    return rows


def toggle_framework_doc_lock(doc_id: str, locked: bool) -> bool:
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE cy_comp_policy_docs SET locked = %s, updated_at = NOW() "
                "WHERE id = %s AND doc_type = 'framework';",
                (locked, doc_id)
            )
            return cur.rowcount > 0
    except Exception as exc:
        log.error("toggle_framework_doc_lock(%s): %s", doc_id, exc)
        return False


def delete_framework_doc(doc_id: str) -> tuple[bool, str]:
    """Returns (success, reason). Fails if document is locked."""
    cymind_doc_id = None
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT cymind_doc_id, locked FROM cy_comp_policy_docs WHERE id = %s AND doc_type = 'framework';",
                (doc_id,)
            )
            row = cur.fetchone()
            if not row:
                return False, "Document not found"
            cymind_doc_id, is_locked = row
            if is_locked:
                return False, "Document is locked. Unlock it first before deleting."
    except Exception as exc:
        log.error("delete_framework_doc lookup: %s", exc)
        return False, str(exc)

    if cymind_doc_id:
        try:
            requests.delete(_rag_url(f"documents/{cymind_doc_id}"), headers=_auth_header(), timeout=8)
        except Exception as exc:
            log.warning("delete_framework_doc CyMind: %s", exc)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_policy_docs WHERE id = %s;", (doc_id,))
            return cur.rowcount > 0, "ok"
    except Exception as exc:
        log.error("delete_framework_doc DB: %s", exc)
        return False, str(exc)


def query_for_question(question_text: str, top_k: int = 5) -> list[str]:
    """
    Query the org-policies collection for chunks relevant to a single questionnaire question.
    Returns a list of plain-text chunks (empty list if CyMind unavailable or nothing relevant).
    Uses a conservative relevance threshold (0.45) so only genuinely related policy text
    is returned — lower confidence chunks produce false scoring signals.
    """
    try:
        resp = requests.get(
            _rag_url("query/multi"),
            headers=_headers(),
            params={
                "collections": _cymind_collection_id("org-policies"),  # "policy-orgpolicies"
                "query":       question_text,
                "top_k":       top_k,
                "threshold":   0.35,  # lowered from 0.45 — conservative but not overly strict
            },
            timeout=15,
        )
        if not resp.ok:
            log.debug("query_for_question: CyMind %s", resp.status_code)
            return []
        data = resp.json()
        # CyMind multi-query response shapes:
        #   {"results": [{"text": "...", "score": 0.87, "collection": "..."}, ...]}
        #   {"chunks": [...]}
        results = data.get("results") or data.get("chunks") or []
        return [r["text"] for r in results if isinstance(r, dict) and r.get("text")]
    except Exception as exc:
        log.debug("query_for_question: CyMind unavailable: %s", exc)
        return []


# ── Multi-framework document upload ──────────────────────────────────────────

_ALL_FRAMEWORK_KEYS = [
    "iso27001", "nis2", "dora", "soc2", "nist_csf", "pci_dss", "gdpr", "eu_ai_act",
]

_FRAMEWORK_LABELS = {
    "iso27001":  "ISO 27001",
    "nis2":      "NIS2",
    "dora":      "DORA",
    "soc2":      "SOC 2",
    "nist_csf":  "NIST CSF 2.0",
    "pci_dss":   "PCI DSS",
    "gdpr":      "GDPR",
    "eu_ai_act": "EU AI Act",
}

# Keyword heuristics for fast local detection (no LLM call required for obvious cases)
_FRAMEWORK_KEYWORDS: dict[str, list[str]] = {
    "iso27001":  ["iso 27001", "iso27001", "isms", "annex a", "27001"],
    "nis2":      ["nis2", "nis 2", "network and information security directive", "art.21", "art.23"],
    "dora":      ["dora", "digital operational resilience", "ictrmf", "art.5", "tlpt"],
    "soc2":      ["soc 2", "soc2", "trust service criteria", "tsc", "aicpa"],
    "nist_csf":  ["nist csf", "nist cybersecurity framework", "identify protect detect respond recover",
                  "pr.aa", "de.cm", "rs.ma"],
    "pci_dss":   ["pci dss", "pci-dss", "cardholder data", "cde", "payment card", "req 1", "req 12"],
    "gdpr":      ["gdpr", "general data protection regulation", "data subject", "dpa", "ropa",
                  "data protection", "personal data"],
    "eu_ai_act": ["eu ai act", "ai act", "high-risk ai", "gpai", "conformity assessment", "annex iii"],
}


def detect_frameworks_from_document(filename: str, cymind_doc_id: Optional[str] = None) -> list[str]:
    """
    Detect which compliance frameworks a policy document is likely to address.

    Strategy:
      1. Keyword scan on filename (fast, no network call).
      2. If CyMind is available and cymind_doc_id is set, ask the LLM via /api/v1/chat.
      3. Fall back to keyword result if LLM unavailable.

    Returns list of framework keys from _ALL_FRAMEWORK_KEYS.
    """
    # Step 1: keyword scan on filename
    name_lower = filename.lower()
    keyword_hits: set[str] = set()
    for fw, keywords in _FRAMEWORK_KEYWORDS.items():
        if any(kw in name_lower for kw in keywords):
            keyword_hits.add(fw)

    # Generic policy document names → assume all security frameworks
    generic_triggers = ["information security policy", "isms policy", "security policy",
                        "cybersecurity policy", "data protection policy", "privacy policy"]
    is_generic = any(t in name_lower for t in generic_triggers)

    # Step 2: attempt LLM detection if CyMind is available
    if cymind_doc_id:
        try:
            labels = ", ".join(
                f"{k} ({_FRAMEWORK_LABELS[k]})" for k in _ALL_FRAMEWORK_KEYS
            )
            prompt = (
                f"A compliance policy document named '{filename}' has been uploaded. "
                f"Based only on the filename, which of these compliance frameworks does it most likely address? "
                f"Available frameworks: {labels}. "
                f"Return ONLY a JSON array of framework keys from the list, e.g. [\"iso27001\", \"gdpr\"]. "
                f"If uncertain, return an empty array []."
            )
            url = get_cymind_url()
            key = get_cymind_api_key()
            if key:
                resp = requests.post(
                    f"{url}/api/v1/chat",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={"message": prompt, "stream": False},
                    timeout=15,
                )
                if resp.ok:
                    content = resp.json().get("content", "") or ""
                    import re, json as _json
                    match = re.search(r'\[.*?\]', content, re.DOTALL)
                    if match:
                        detected = _json.loads(match.group())
                        valid = [fw for fw in detected if fw in _ALL_FRAMEWORK_KEYS]
                        if valid:
                            log.info("detect_frameworks: LLM detected %s for '%s'", valid, filename)
                            return valid
        except Exception as exc:
            log.debug("detect_frameworks: LLM call failed (%s), using keyword fallback", exc)

    # Step 3: return keyword hits or all frameworks for generic policy docs
    if keyword_hits:
        return sorted(keyword_hits)
    if is_generic:
        return list(_ALL_FRAMEWORK_KEYS)
    # Default: no specific framework detected — map to all security frameworks except EU AI Act
    return ["iso27001", "nis2", "dora", "soc2", "nist_csf", "pci_dss"]


def upload_document_multi_framework(
    file_storage,
    metadata: dict,
    uploaded_by: str,
) -> dict:
    """
    Upload a policy document to the shared org-policies collection once,
    then auto-detect which compliance frameworks it covers and persist them
    in cy_comp_policy_docs.mapped_frameworks[].

    metadata may contain: framework (hint), tag

    Returns the doc record enriched with detected_frameworks.
    """
    doc_id    = str(uuid.uuid4())
    filename  = file_storage.filename or "document"
    tag       = metadata.get("tag") or None
    fw_hint   = metadata.get("framework") or None
    file_size = None

    # All org-policy documents go into the shared collection
    collection_id = "policy-orgpolicies"

    cymind_doc_id = None
    try:
        file_bytes = file_storage.read()
        file_size  = len(file_bytes)
        file_storage.seek(0)
        files = {
            "file": (filename, file_bytes, file_storage.content_type or "application/octet-stream")
        }
        resp = requests.post(
            _rag_url(f"collections/{collection_id}/upload"),
            headers=_auth_header(),
            files=files,
            params={"chunk_size": 512, "overlap": 64},
            timeout=60,
        )
        if resp.ok:
            rd = resp.json()
            cymind_doc_id = rd.get("doc_id") or rd.get("id")
            log.info("upload_document_multi: CyMind accepted %s → doc_id=%s", filename, cymind_doc_id)
        else:
            log.warning("upload_document_multi: CyMind %s %s", resp.status_code, resp.text[:300])
    except Exception as exc:
        log.error("upload_document_multi: CyMind upload failed: %s", exc)

    # Detect frameworks
    detected_frameworks = detect_frameworks_from_document(filename, cymind_doc_id)
    # If caller provided a framework hint, ensure it is included
    if fw_hint and fw_hint in _ALL_FRAMEWORK_KEYS and fw_hint not in detected_frameworks:
        detected_frameworks = [fw_hint] + detected_frameworks

    # Primary framework for legacy 'framework' column = hint or first detected
    primary_fw = fw_hint or (detected_frameworks[0] if detected_frameworks else "general")

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_policy_docs
                    (id, name, file_type, collection_id, cymind_doc_id,
                     framework, mapped_frameworks, indexed,
                     uploaded_by, doc_type, tag, file_size, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'policy',%s,%s,NOW(),NOW());
                """,
                (
                    doc_id, filename,
                    filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin",
                    collection_id, cymind_doc_id,
                    primary_fw, detected_frameworks,
                    bool(cymind_doc_id),
                    uploaded_by, tag, file_size,
                )
            )
    except Exception as exc:
        log.error("upload_document_multi DB persist: %s", exc)

    return {
        "id":                 doc_id,
        "name":               filename,
        "collection_id":      collection_id,
        "cymind_doc_id":      cymind_doc_id,
        "framework":          primary_fw,
        "detected_frameworks": detected_frameworks,
        "tag":                tag,
        "file_size":          file_size,
        "indexed":            bool(cymind_doc_id),
        "uploaded_by":        uploaded_by,
        "doc_type":           "policy",
    }


def query_for_compliance(description: str, top_k: int = 3) -> dict:
    """
    Query all active policy collections to find which compliance frameworks
    are potentially implicated by an alert description.
    Returns {frameworks: [...], chunks: [...], confidence: float}
    """
    try:
        resp = requests.get(
            _rag_url("query/multi"),
            headers=_headers(),
            params={
                "collections": "policy-iso27001,policy-nis2,policy-dora,policy-soc2,policy-nist-csf,policy-pcidss",
                "query": description,
                "top_k": top_k,
                "threshold": 0.35,
            },
            timeout=10,
        )
        if resp.ok:
            return resp.json()
    except Exception as exc:
        log.debug("query_for_compliance: CyMind unavailable: %s", exc)
    return {}
