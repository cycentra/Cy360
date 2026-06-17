"""
ueba_ml.py
ML-backed UEBA layer — IsolationForest per-user anomaly detection.
Uses Isolation Forest (sklearn) for unsupervised anomaly detection.

Deployment modes (set via UEBA_ML_SHADOW_MODE env var in cysiemstack.env):
  true  (default) — shadow mode: detects and LOGS anomalies only. No risk score impact.
                    Use this for at least 7 days to validate detection quality.
  false           — live mode: detected anomalies create UEBAAnomaly records and
                    contribute 15 pts to the incident risk score (advisory weight).

Promotion steps:
  1. Run in shadow mode for ≥7 days.
  2. Review logs for 'ml_shadow_anomaly' entries: grep UEBA_ML_SHADOW_MODE cysiemstack.log
  3. Tune UEBA_ML_CONTAMINATION if FP rate is high (lower value = fewer anomalies).
  4. Set UEBA_ML_SHADOW_MODE=false in /opt/cycentra/cysiemstack.env and restart.
  5. Monitor 'ml_behavioural' anomaly type in UEBA dashboard for 2 weeks.

Feature vector (14 features as of MODEL_FEATURE_VERSION=2):
  0  sin(hour * 2π/24)   — cyclic time encoding (avoids 23→0 discontinuity)
  1  cos(hour * 2π/24)   — cyclic time encoding (pair)
  2  is_weekend          — 1 if Saturday or Sunday
  3  rule_level          — Wazuh rule level (3-15)
  4  base_score          — normalised risk score (4.1-8.2)
  5  recent_fails        — auth failure count in 2h window
  6  recent_agents       — unique hosts in 2h window
  7  recent_count        — total events in 2h window
  8  has_src_ip          — 1 if alert has an external src IP
  9  is_success_login    — 1 if rule fires on successful auth (5715/5718)
  10 recent_privesc      — privilege escalation events in 2h window
  11 recent_fim          — FIM (file-change) events in 2h window
  12 has_mitre_tag       — 1 if alert carries a MITRE ATT&CK technique ID
  13 is_off_hours        — 1 if hour outside 07:00-19:00

Models are retrained weekly from historical alert data.
Stored in /app/ml_models/ inside the container (persisted via Docker volume).

MODEL_FEATURE_VERSION is stamped into each saved model.  If a loaded model's
version does not match the current version, it is discarded and the user's model
is re-queued for training — this prevents crashes when features are added.
"""
import os
import math
import pickle
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import UEBAAnomaly, Alert, Incident
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

# UEBA_ML_SHADOW_MODE: set to 'false' in cysiemstack.env to promote to live.
# Default is 'true' (shadow / validation mode).
SHADOW_MODE    = os.getenv('UEBA_ML_SHADOW_MODE', 'true').lower() == 'true'
MIN_TRAIN_DAYS = int(os.getenv('UEBA_ML_MIN_TRAIN_DAYS', '7'))
MODEL_DIR      = Path(settings.ueba_ml_model_dir)
CONTAMINATION  = float(os.getenv('UEBA_ML_CONTAMINATION', '0.05'))

# Increment this when the feature vector changes.  Saved models carry this
# version; a mismatch causes the stale model to be evicted and re-trained.
MODEL_FEATURE_VERSION = 2

# Log shadow mode state at startup so operators can confirm current config
if SHADOW_MODE:
    log.warning('ueba_ml_shadow_mode',
                msg='ML UEBA is in SHADOW MODE — anomalies logged but NOT scored. '
                    'Set UEBA_ML_SHADOW_MODE=false to promote to live detection.')
else:
    log.info('ueba_ml_live_mode',
             msg='ML UEBA is in LIVE MODE — behavioural anomalies will affect risk scores.')

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# In-memory model cache: username → (model_object, file_mtime)
# Avoids repeated pickle.load() on every alert — critical on 4-CPU / 8 GB servers.
_model_cache: dict[str, tuple] = {}

_PRIVESC_IDS   = frozenset({5400, 5402, 5501, 18101, 18104})
_AUTH_SUCCESS  = frozenset({5715, 5718})


def _feature_vector(alert: dict, recent: list[dict]) -> list[float]:
    """Convert alert + context into a 14-feature numeric vector.

    Features use cyclic sin/cos encoding for hour-of-day so that 23:00 and
    00:00 are recognised as temporally adjacent (they would be at opposite ends
    of a raw 0-23 linear feature).
    """
    ts   = alert.get('timestamp') or datetime.now(timezone.utc)
    hour = ts.hour if hasattr(ts, 'hour') else 12
    dow  = ts.weekday() if hasattr(ts, 'weekday') else 0  # 0=Mon … 6=Sun

    recent_fails   = sum(1 for a in recent if a.get('rule_id') in {5710, 5711, 5716})
    recent_agents  = len({a.get('agent_id') for a in recent if a.get('agent_id')})
    recent_count   = len(recent)
    recent_privesc = sum(1 for a in recent if a.get('rule_id') in _PRIVESC_IDS)
    recent_fim     = sum(1 for a in recent if a.get('category') == 'fim')

    return [
        math.sin(hour * 2 * math.pi / 24),                         # 0: cyclic hour (sin)
        math.cos(hour * 2 * math.pi / 24),                         # 1: cyclic hour (cos)
        float(1 if dow >= 5 else 0),                               # 2: is_weekend
        float(alert.get('rule_level', 0)),                          # 3: rule level
        float(alert.get('base_score', 0)),                          # 4: base risk score
        float(recent_fails),                                        # 5: recent auth failures
        float(recent_agents),                                       # 6: unique agents in window
        float(recent_count),                                        # 7: total events in window
        float(1 if alert.get('src_ip') else 0),                    # 8: has external src_ip
        float(1 if alert.get('rule_id') in _AUTH_SUCCESS else 0),  # 9: is success login
        float(recent_privesc),                                      # 10: privesc events in window
        float(recent_fim),                                          # 11: FIM events in window
        float(1 if alert.get('mitre_id') else 0),                  # 12: has MITRE tag
        float(1 if not (7 <= hour <= 19) else 0),                  # 13: is off-hours
    ]


def _load_model(username: str):
    """Load trained model for a user.
    Uses an in-memory cache keyed by file mtime — avoids pickle.load on every alert.
    Returns None if not trained yet or if the saved model's feature version is stale.
    """
    model_path = MODEL_DIR / f"{username.replace('/', '_')}.pkl"
    if not model_path.exists():
        return None

    try:
        current_mtime = model_path.stat().st_mtime
        cached = _model_cache.get(username)
        if cached and cached[1] == current_mtime:
            return cached[0]                          # cache hit — no disk I/O
        with open(model_path, 'rb') as f:
            payload = pickle.load(f)
        # Saved models are stored as {'version': int, 'model': IsolationForest}
        # when version-stamped; bare IsolationForest objects are pre-v2 (stale).
        if not isinstance(payload, dict):
            log.info('ml_model_stale', username=username,
                     reason='pre-v2 format, will retrain on next weekly cycle')
            return None
        if payload.get('version') != MODEL_FEATURE_VERSION:
            log.info('ml_model_stale', username=username,
                     saved_version=payload.get('version'),
                     current_version=MODEL_FEATURE_VERSION,
                     reason='feature vector version mismatch, will retrain')
            return None
        model = payload['model']
        _model_cache[username] = (model, current_mtime)
        return model
    except Exception:
        return None


def _save_model(username: str, model) -> None:
    model_path = MODEL_DIR / f"{username.replace('/', '_')}.pkl"
    try:
        payload = {'version': MODEL_FEATURE_VERSION, 'model': model}
        with open(model_path, 'wb') as f:
            pickle.dump(payload, f)
        # Evict stale cache entry so next load picks up the new mtime
        _model_cache.pop(username, None)
    except Exception as e:
        log.warning('ml_model_save_error', username=username, error=str(e))


async def ml_analyse_alert(
    db: AsyncSession,
    alert: dict,
    recent: list[dict],
    incident_id: str,
) -> list[UEBAAnomaly]:
    """
    Run ML anomaly detection on a single alert.
    Returns list of UEBAAnomaly objects (empty in shadow mode; populated when live).
    """
    username = alert.get('username')
    if not username:
        return []

    model = _load_model(username)
    if model is None:
        return []  # Not enough data to train yet

    try:
        features = [_feature_vector(alert, recent)]
        prediction = model.predict(features)   # -1 = anomaly, 1 = normal
        score      = model.decision_function(features)[0]  # negative = more anomalous
    except Exception as e:
        log.debug('ml_predict_error', username=username, error=str(e))
        return []

    if prediction[0] == 1:  # Normal
        return []

    # Anomaly detected
    description = (
        f"[ML] Behavioural anomaly (score {score:.2f}) — "
        f"unusual pattern for {username} at hour {alert.get('timestamp', datetime.now()).hour}:00 "
        f"on {alert.get('agent_name', alert.get('agent_id'))}"
    )

    if SHADOW_MODE:
        log.info('ml_shadow_anomaly',
                 username=username,
                 score=round(score, 4),
                 incident_id=incident_id,
                 hour=alert.get('timestamp', datetime.now()).hour,
                 agent=alert.get('agent_name', alert.get('agent_id')),
                 rule_id=alert.get('rule_id'),
                 hint='Set UEBA_ML_SHADOW_MODE=false in cysiemstack.env to promote to live mode')
        return []  # Shadow mode: log but don't create anomaly records

    # Live mode: create anomaly record with lower risk contribution than rule detectors
    anomaly = UEBAAnomaly(
        username          = username,
        anomaly_type      = 'ml_behavioural',
        description       = description,
        risk_contribution = 15,  # Intentionally low — ML is advisory
        alert_ids         = [str(alert.get('wazuh_id'))] if alert.get('wazuh_id') else [],
        incident_id       = incident_id,
        resolved          = False,
    )
    db.add(anomaly)
    await db.flush()
    return [anomaly]


async def retrain_all_models(db: AsyncSession) -> None:
    """
    Retrain ML models for all users with sufficient data.
    Called weekly by the background scheduler.

    FP exclusion: alerts belonging to analyst-confirmed false-positive incidents
    are removed from the training set.  Training on FP events would teach the
    model that noisy/benign activity is 'normal', suppressing future anomaly
    detection for that user.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        log.warning('sklearn_not_installed',
                    msg='pip install scikit-learn to enable ML UEBA')
        return

    min_cutoff = datetime.now(timezone.utc) - timedelta(days=MIN_TRAIN_DAYS)

    # Collect incident IDs that analysts confirmed as false positives so we can
    # exclude their alerts from the training data.
    fp_incidents_q = await db.execute(
        select(Incident.id).where(
            Incident.status.in_(['false_positive', 'closed']),
            Incident.false_positive_reason.isnot(None),
            Incident.updated_at >= min_cutoff,
        )
    )
    fp_incident_ids = {row[0] for row in fp_incidents_q.all()}
    log.info('ml_retrain_fp_exclusion', fp_incident_count=len(fp_incident_ids))

    # Get all users with sufficient data
    users_q = await db.execute(
        select(Alert.username)
        .where(Alert.username.isnot(None), Alert.timestamp >= min_cutoff)
        .distinct()
    )
    usernames = [row[0] for row in users_q.all()]

    trained = 0
    for username in usernames:
        # Fetch training data, excluding alerts from FP-confirmed incidents
        alerts_q = await db.execute(
            select(Alert).where(
                Alert.username == username,
                Alert.timestamp >= min_cutoff,
                Alert.incident_id.notin_(fp_incident_ids) if fp_incident_ids else True,
            ).order_by(Alert.timestamp).limit(5000)
        )
        alerts = alerts_q.scalars().all()

        if len(alerts) < 30:
            continue  # Too little data

        # Build feature matrix
        features = []
        for i, a in enumerate(alerts):
            # Build a minimal recent context (last 10 alerts for the user)
            ctx = [
                {
                    'rule_id':   x.rule_id,
                    'agent_id':  x.agent_id,
                    'timestamp': x.timestamp,
                    'category':  x.category,
                }
                for x in alerts[max(0, i - 10):i]
            ]
            try:
                fv = _feature_vector({
                    'rule_id':    a.rule_id,
                    'rule_level': a.rule_level,
                    'base_score': float(a.base_score or 0),
                    'src_ip':     str(a.src_ip) if a.src_ip else None,
                    'agent_id':   a.agent_id,
                    'agent_name': a.agent_name,
                    'timestamp':  a.timestamp,
                    'mitre_id':   a.mitre_id,
                    'category':   a.category,
                }, ctx)
                features.append(fv)
            except Exception:
                continue

        if len(features) < 20:
            continue

        try:
            model = IsolationForest(
                contamination=CONTAMINATION,
                random_state=42,
                n_estimators=100,
            )
            model.fit(features)
            _save_model(username, model)
            trained += 1
        except Exception as e:
            log.warning('ml_train_error', username=username, error=str(e))

    log.info('ml_retrain_complete', models_trained=trained, total_users=len(usernames))
