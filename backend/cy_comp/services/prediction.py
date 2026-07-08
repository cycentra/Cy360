"""
cy_comp/services/prediction.py
================================
Predictive risk modeling using linear regression + EWMA on score history.

Pure-Python implementation — no external ML libraries.
Reads from cy_comp_framework_scores (written by compute_framework_scores()).
Returns predictions at 30/60/90 day horizons with confidence bounds.
"""

import logging
from datetime import datetime, timedelta, timezone

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.prediction")

SUPPORTED_HORIZONS = (30, 60, 90)
EWMA_ALPHA = 0.3   # more weight on recent observations


def predict_framework_score(framework: str, horizons: tuple[int, ...] = SUPPORTED_HORIZONS) -> dict:
    """
    Predict future compliance score for a single framework.

    Returns a dict with:
      framework, data_points, trend, slope_per_day, r_squared,
      current_score, predictions{30/60/90: {score, low, high, confidence}},
      actual (list of {days, date, score, ewma})
    """
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT score, computed_at
                FROM cy_comp_framework_scores
                WHERE framework = %s
                ORDER BY computed_at ASC
                LIMIT 90;
                """,
                (framework,),
            )
            rows = cur.fetchall()
    except Exception as exc:
        log.error("prediction: DB read for %s: %s", framework, exc)
        return {"framework": framework, "error": str(exc), "data_points": 0}

    if not rows:
        return {
            "framework":     framework,
            "data_points":   0,
            "status":        "warming_up",
            "message":       "No score history yet — trigger a dashboard refresh to populate history.",
            "predictions":   {},
            "actual":        [],
        }

    # Normalise timestamps to UTC-aware
    def _utc(ts):
        if ts is None:
            return datetime.now(timezone.utc)
        if hasattr(ts, "tzinfo") and ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    t0 = _utc(rows[0][1])
    xs, ys = [], []
    for score, ts in rows:
        days = (_utc(ts) - t0).total_seconds() / 86400.0
        xs.append(days)
        ys.append(float(score or 0.0))

    n = len(xs)

    # ── Linear regression: y = a + b*x ──────────────────────────────────────
    sum_x  = sum(xs)
    sum_y  = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_x2 = sum(x ** 2 for x in xs)

    denom = n * sum_x2 - sum_x ** 2
    if abs(denom) < 1e-9:
        slope     = 0.0
        intercept = sum_y / n
    else:
        slope     = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n

    # ── R² ───────────────────────────────────────────────────────────────────
    y_mean = sum_y / n
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    r2 = (1.0 - ss_res / ss_tot) if ss_tot > 1e-9 else 0.0

    # ── EWMA series ──────────────────────────────────────────────────────────
    ewma = ys[0]
    ewma_series = [round(ewma, 1)]
    for y in ys[1:]:
        ewma = EWMA_ALPHA * y + (1.0 - EWMA_ALPHA) * ewma
        ewma_series.append(round(ewma, 1))

    # ── Trend label ──────────────────────────────────────────────────────────
    if n >= 2:
        daily_slope = (ys[-1] - ys[0]) / max(xs[-1] - xs[0], 1.0)
    else:
        daily_slope = 0.0

    if daily_slope > 0.1:
        trend = "improving"
    elif daily_slope < -0.1:
        trend = "declining"
    else:
        trend = "stable"

    # ── Residual std-dev for confidence intervals ─────────────────────────────
    std_dev = (ss_res / n) ** 0.5 if n > 1 else 10.0

    # ── Current x (days from t0 to now) ──────────────────────────────────────
    now    = datetime.now(timezone.utc)
    x_now  = (now - t0).total_seconds() / 86400.0

    # ── Predictions ──────────────────────────────────────────────────────────
    predictions: dict[str, dict] = {}
    for h in horizons:
        x_future  = x_now + h
        raw_pred  = intercept + slope * x_future
        pred_score = round(max(0.0, min(100.0, raw_pred)), 1)

        # Confidence: R² (quality) + data volume bonus; more horizon = less confident
        conf = min(95.0, max(10.0, r2 * 65.0 + min(n, 20) * 1.25 - h * 0.15))
        margin = round(min(30.0, std_dev * 1.5 * (1.0 + h / 90.0)), 1)

        predictions[str(h)] = {
            "score":      pred_score,
            "confidence": int(conf),
            "low":        round(max(0.0,   pred_score - margin), 1),
            "high":       round(min(100.0, pred_score + margin), 1),
        }

    # ── Historical series for chart ──────────────────────────────────────────
    actual = [
        {
            "days":  round(x, 1),
            "date":  (t0 + timedelta(seconds=x * 86400)).strftime("%Y-%m-%d"),
            "score": y,
            "ewma":  ewma_series[i],
        }
        for i, (x, y) in enumerate(zip(xs, ys))
    ]

    return {
        "framework":    framework,
        "data_points":  n,
        "trend":        trend,
        "slope_per_day": round(slope, 4),
        "r_squared":    round(r2, 3),
        "current_score": ys[-1],
        "predictions":  predictions,
        "actual":       actual,
        "computed_at":  now.isoformat(),
    }


def predict_all_frameworks(frameworks: list[str] | None = None) -> dict[str, dict]:
    """
    Return predictions for all (or specified) frameworks.

    Returns {framework_id: predict_framework_score(fw)} mapping.
    """
    from cy_comp.services.compliance import SUPPORTED_FRAMEWORKS
    targets = frameworks or SUPPORTED_FRAMEWORKS
    return {fw: predict_framework_score(fw) for fw in targets}


def get_portfolio_trend(frameworks: list[str] | None = None) -> dict:
    """
    Aggregate 30-day prediction across all frameworks to give a portfolio-level view.

    Returns {overall_direction, count_improving, count_declining, count_stable, by_framework}.
    """
    from cy_comp.services.compliance import SUPPORTED_FRAMEWORKS
    targets = frameworks or SUPPORTED_FRAMEWORKS

    improving = declining = stable = no_data = 0
    by_fw: list[dict] = []

    for fw in targets:
        result = predict_framework_score(fw)
        trend  = result.get("trend", "unknown")
        pred30 = result.get("predictions", {}).get("30", {})

        if result.get("data_points", 0) == 0:
            no_data += 1
        elif trend == "improving":
            improving += 1
        elif trend == "declining":
            declining += 1
        else:
            stable += 1

        by_fw.append({
            "framework":     fw,
            "trend":         trend,
            "current_score": result.get("current_score"),
            "score_30d":     pred30.get("score"),
            "confidence_30d": pred30.get("confidence"),
            "data_points":   result.get("data_points", 0),
        })

    if improving > declining:
        direction = "improving"
    elif declining > improving:
        direction = "declining"
    else:
        direction = "mixed"

    return {
        "overall_direction": direction,
        "count_improving":   improving,
        "count_declining":   declining,
        "count_stable":      stable,
        "count_no_data":     no_data,
        "by_framework":      by_fw,
        "computed_at":       datetime.now(timezone.utc).isoformat(),
    }
