"""
ueba_ml.py
ML-backed UEBA layer — runs in shadow mode alongside the rule engine.
Uses Isolation Forest (sklearn) for unsupervised anomaly detection.

Shadow mode (default): detects anomalies but does NOT affect risk scores or alerts.
Set UEBA_ML_SHADOW_MODE=false only after validating ML detections for ≥1 week.

Models are retrained weekly from historical alert data.
Stored in /app/ml_models/ inside the container (persisted via Docker volume).
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
from models import UEBAAnomaly, Alert
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

SHADOW_MODE    = os.getenv('UEBA_ML_SHADOW_MODE', 'true').lower() == 'true'
MIN_TRAIN_DAYS = int(os.getenv('UEBA_ML_MIN_TRAIN_DAYS', '7'))
MODEL_DIR      = Path(settings.ueba_ml_model_dir)
CONTAMINATION  = float(os.getenv('UEBA_ML_CONTAMINATION', '0.05'))

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# In-memory model cache: username → (model_object, file_mtime)
# Avoids repeated pickle.load() on every alert — critical on 4-CPU / 8 GB servers.
_model_cache: dict[str, tuple] = {}


def _feature_vector(alert: dict, recent: list[dict]) -> list[float]:
    """Convert alert + context into a numeric feature vector."""
    ts   = alert.get('timestamp') or datetime.now(timezone.utc)
    hour = ts.hour if hasattr(ts, 'hour') else 12

    recent_fails  = sum(1 for a in recent if a.get('rule_id') in {5710, 5711, 5716})
    recent_agents = len({a.get('agent_id') for a in recent if a.get('agent_id')})
    recent_count  = len(recent)

    return [
        float(hour),                                    # hour of day (0-23)
        float(alert.get('rule_level', 0)),              # rule level
        float(alert.get('base_score', 0)),              # base risk score
        float(recent_fails),                            # recent auth failures
        float(recent_agents),                           # unique agents in window
        float(recent_count),                            # total events in window
        float(1 if alert.get('src_ip') else 0),        # has external src_ip
        float(1 if alert.get('rule_id') in {5715, 5718} else 0),  # is success login
    ]


def _load_model(username: str):
    """Load trained model for a user.
    Uses an in-memory cache keyed by file mtime — avoids pickle.load on every alert.
    Returns None if not trained yet.
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
            model = pickle.load(f)
        _model_cache[username] = (model, current_mtime)
        return model
    except Exception:
        return None


def _save_model(username: str, model) -> None:
    model_path = MODEL_DIR / f"{username.replace('/', '_')}.pkl"
    try:
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
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
        log.info('ml_shadow_anomaly', username=username, score=score, incident_id=incident_id)
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
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        log.warning('sklearn_not_installed',
                    msg='pip install scikit-learn to enable ML UEBA')
        return

    min_cutoff = datetime.now(timezone.utc) - timedelta(days=MIN_TRAIN_DAYS)

    # Get all users with sufficient data
    users_q = await db.execute(
        select(Alert.username)
        .where(Alert.username.isnot(None), Alert.timestamp >= min_cutoff)
        .distinct()
    )
    usernames = [row[0] for row in users_q.all()]

    trained = 0
    for username in usernames:
        # Fetch training data
        alerts_q = await db.execute(
            select(Alert).where(
                Alert.username == username,
                Alert.timestamp >= min_cutoff,
            ).order_by(Alert.timestamp).limit(5000)
        )
        alerts = alerts_q.scalars().all()

        if len(alerts) < 30:
            continue  # Too little data

        # Build feature matrix
        features = []
        for a in alerts:
            # Build a minimal recent context (last 5 alerts for the user)
            ctx = [{'rule_id': x.rule_id, 'agent_id': x.agent_id, 'timestamp': x.timestamp}
                   for x in alerts[max(0, alerts.index(a)-5):alerts.index(a)]]
            try:
                fv = _feature_vector({
                    'rule_id': a.rule_id, 'rule_level': a.rule_level,
                    'base_score': float(a.base_score or 0),
                    'src_ip': str(a.src_ip) if a.src_ip else None,
                    'agent_id': a.agent_id, 'agent_name': a.agent_name,
                    'timestamp': a.timestamp,
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
