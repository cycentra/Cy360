"""
Regression tests — FP auto-close threshold, cloud entity risk, UEBA usernames,
cloud category upgrade.

Bug 1: FP auto-close threshold — incidents with fp_probability >= fpThreshold
       should advance to 'closed' (not 'false_positive') via advance_incident_status().

Bug 2: Cloud entity risk — O365 alerts should create/update a 'Microsoft 365'
       entity in risk_scores, not be silently merged into the host agent.

Bug 3: UEBA username extraction — 'root' and O365 email addresses must be
       extracted from alerts (not excluded).

Bug 4: Cloud category upgrade — when a specific cloud alert (o365) merges into
       an incident with legacy 'cloud' category, 'cloud' is replaced by 'o365'.
"""
import sys
import os
import json
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(status="investigating", fp_prob=0.0):
    inc = MagicMock()
    inc.id                  = "INC-00001"
    inc.status              = status
    inc.fp_probability      = fp_prob
    inc.iris_case_id        = None
    inc.severity            = "medium"
    inc.alert_count         = 2
    inc.false_positive_reason = None
    inc.closed_at           = None
    inc.updated_at          = None
    return inc


# ===========================================================================
# Bug 1 — advance_incident_status() uses fpThreshold as DIRECT auto-close
# ===========================================================================

class TestFPAutoClose:
    """advance_incident_status: fp >= threshold → closed (not false_positive)."""

    @pytest.fixture(autouse=True)
    def _patch_deps(self, monkeypatch):
        # Patch _load_iris_config to return threshold=60
        monkeypatch.setattr(
            "cysiemstack.correlation_engine.iris_connector._load_iris_config",
            lambda: {"fp_threshold": 60.0, "mode": "cloud",
                     "url": "https://x", "api_key": "k", "customer_id": 1},
        )
        # Patch write_audit to no-op
        monkeypatch.setattr(
            "cysiemstack.correlation_engine.iris_connector.write_audit",
            AsyncMock(),
        )

    @pytest.mark.asyncio
    async def test_fp_above_threshold_sets_closed(self):
        """FP prob 70 >= threshold 60 → incident.status == 'closed'."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from iris_connector import advance_incident_status

        db  = AsyncMock()
        inc = _make_incident(status="investigating")

        new_status, _ = await advance_incident_status(db, inc, fp_score=70.0,
                                                       actor="system", enriched=True)

        assert new_status == "closed", (
            f"Expected 'closed', got '{new_status}'. "
            "fp=70 >= threshold=60 must auto-close directly to 'closed'."
        )
        assert inc.status == "closed"

    @pytest.mark.asyncio
    async def test_fp_below_threshold_does_not_close(self):
        """FP prob 50 < threshold 60 → incident must NOT be closed."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from iris_connector import advance_incident_status

        db  = AsyncMock()
        inc = _make_incident(status="investigating")

        new_status, _ = await advance_incident_status(db, inc, fp_score=50.0,
                                                       actor="system", enriched=True)

        assert new_status != "closed", (
            f"fp=50 < threshold=60 should NOT close the incident (got '{new_status}')."
        )
        assert inc.status != "closed"

    @pytest.mark.asyncio
    async def test_already_closed_not_modified(self):
        """Incident already 'closed' must not be re-processed."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from iris_connector import advance_incident_status

        db  = AsyncMock()
        inc = _make_incident(status="closed")
        original_closed_at = inc.closed_at

        new_status, _ = await advance_incident_status(db, inc, fp_score=80.0,
                                                       actor="system", enriched=True)

        assert new_status == "closed"
        # closed_at should NOT have been overwritten
        assert inc.closed_at == original_closed_at


# ===========================================================================
# Bug 2 — Cloud entity risk scoring
# ===========================================================================

class TestCloudEntityNames:
    """CLOUD_ENTITY_NAMES must exist and contain standard cloud sources."""

    def test_cloud_entity_names_defined(self):
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from risk_scorer import CLOUD_ENTITY_NAMES

        assert "o365" in CLOUD_ENTITY_NAMES, "'o365' missing from CLOUD_ENTITY_NAMES"
        assert CLOUD_ENTITY_NAMES["o365"] == "Microsoft 365"
        assert "azure" in CLOUD_ENTITY_NAMES
        assert "aws"   in CLOUD_ENTITY_NAMES

    def test_calculate_entity_risk_accepts_cloud_type(self):
        """calculate_entity_risk must accept entity_type='cloud' without raising."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        import inspect
        from risk_scorer import calculate_entity_risk

        sig = inspect.signature(calculate_entity_risk)
        params = list(sig.parameters.keys())
        assert "entity_type" in params, "entity_type parameter missing"


# ===========================================================================
# Bug 3 — _extract_username must include 'root' and O365 emails
# ===========================================================================

class TestExtractUsername:
    """_extract_username must not filter 'root' and must parse O365 fields."""

    @pytest.fixture(autouse=True)
    def _import(self):
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from normaliser import _extract_username
        self._fn = _extract_username

    def test_root_username_extracted(self):
        """'root' as srcuser must be returned, not silently dropped."""
        alert = {"data": {"srcuser": "root"}}
        result = self._fn(alert)
        assert result == "root", (
            f"Expected 'root', got {result!r}. "
            "'root' must no longer be excluded from UEBA tracking."
        )

    def test_o365_userid_extracted(self):
        """data.office365.UserId email must be returned as username."""
        alert = {
            "data": {
                "office365": {
                    "UserId": "deepak.bhatnagar@secupulse.com",
                    "Operation": "MailItemsAccessed",
                }
            }
        }
        result = self._fn(alert)
        assert result == "deepak.bhatnagar@secupulse.com", (
            f"Expected O365 email, got {result!r}. "
            "data.office365.UserId must be extracted as username."
        )

    def test_o365_mailbox_owner_upn_extracted(self):
        """data.office365.MailboxOwnerUPN email must be returned as username."""
        alert = {
            "data": {
                "office365": {
                    "MailboxOwnerUPN": "owner@example.com",
                }
            }
        }
        result = self._fn(alert)
        assert result == "owner@example.com"

    def test_system_still_excluded(self):
        """'SYSTEM' (Windows) must still be excluded."""
        alert = {"data": {"srcuser": "SYSTEM"}}
        result = self._fn(alert)
        assert result is None, (
            f"'SYSTEM' should be excluded, got {result!r}."
        )

    def test_o365_non_email_userid_skipped(self):
        """data.office365.UserId without '@' must not be returned (e.g. app IDs)."""
        alert = {
            "data": {
                "office365": {
                    "UserId": "31fed4a7-6838-d79d-ab5e-98ee89bbeea3",  # GUID app ID
                }
            }
        }
        result = self._fn(alert)
        assert result is None, (
            f"Non-email UserId should be skipped, got {result!r}."
        )


# ===========================================================================
# Bug 4 — _merge_categories upgrades 'cloud' → specific source
# ===========================================================================

class TestMergeCategories:
    """_merge_categories must replace 'cloud' with specific source when available."""

    @pytest.fixture(autouse=True)
    def _import(self):
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), "../../backend/cysiemstack/correlation_engine"))
        from grouper import _merge_categories
        self._fn = _merge_categories

    def test_cloud_upgraded_to_o365(self):
        """['cloud'] + 'o365' → ['o365'] (legacy 'cloud' replaced)."""
        result = self._fn(["cloud"], "o365")
        assert result == ["o365"], (
            f"Expected ['o365'], got {result}. "
            "Legacy 'cloud' must be replaced by 'o365' on merge."
        )

    def test_cloud_upgraded_to_azure(self):
        result = self._fn(["cloud"], "azure")
        assert "azure" in result
        assert "cloud" not in result

    def test_specific_source_not_duplicated(self):
        """If 'o365' already present, must not be added twice."""
        result = self._fn(["o365"], "o365")
        assert result.count("o365") == 1

    def test_non_cloud_category_unaffected(self):
        """'authentication' category merge must not touch 'cloud' replacement logic."""
        result = self._fn(["cloud", "authentication"], "authentication")
        # 'cloud' stays because 'authentication' is not a specific cloud source
        assert "cloud" in result
        assert "authentication" in result

    def test_empty_existing(self):
        result = self._fn([], "o365")
        assert result == ["o365"]

    def test_none_new_cat_returns_existing(self):
        result = self._fn(["cloud"], None)
        assert result == ["cloud"]
