"""
Flask API serving the phishing Random Forest.

Run:
    pip install -r requirements.txt
    python app.py

Endpoints
    GET  /health         model status and feature count
    POST /predict        {"url": "...", "features": {optional overrides}}
    POST /bulk-scan      {"urls": ["...", ...]}
    GET  /model-metrics  real metrics from the training notebook
    GET  /history        scans performed by this process
    GET  /analytics      aggregates over that history

The response shape of /predict matches exactly what the frontend already
consumes, so no translation layer is needed on the client.

Read the caveat at the top of features.py before treating any prediction as
authoritative — the feature extractor is a reimplementation, not the original.
"""

from __future__ import annotations

import datetime as dt
import os
import threading
import uuid
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import joblib
import numpy as np
from flask import Flask, jsonify, request, redirect, render_template
from flask_cors import CORS

from features import DEGENERATE_FEATURES, FEATURE_ORDER, TRAINING_CLIP_BOUNDS, extract_features
import email_scanner

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing_rf_model.pkl"
SCALER_PATH = BASE_DIR / "models" / "phishing_scaler.pkl"

# The model is binary (phishing vs legitimate). "Suspicious" is a confidence
# band, not a third class — anything the model isn't sure about lands there
# rather than being forced into a verdict it can't support.
PHISHING_THRESHOLD = float(os.environ.get("PHISHING_THRESHOLD", 0.75))
LEGITIMATE_THRESHOLD = float(os.environ.get("LEGITIMATE_THRESHOLD", 0.35))

LOOKUP_TIMEOUT = float(os.environ.get("LOOKUP_TIMEOUT", 4.0))
BULK_WORKERS = int(os.environ.get("BULK_WORKERS", 8))
BULK_MAX_URLS = int(os.environ.get("BULK_MAX_URLS", 200))

# How many features to surface in the per-scan explanation.
EXPLAIN_TOP_N = 8

app = Flask(__name__)
CORS(app)  # Vite dev server runs on a different origin.

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Fail loudly at startup rather than producing quietly wrong scores. A mismatch
# here means FEATURE_ORDER has drifted from what the scaler was fitted on.
_expected = getattr(scaler, "n_features_in_", len(FEATURE_ORDER))
if _expected != len(FEATURE_ORDER):
    raise RuntimeError(
        f"scaler expects {_expected} features but FEATURE_ORDER has "
        f"{len(FEATURE_ORDER)}. Re-copy the header of data/X_train_scaled.csv."
    )

# Confirm class 1 is phishing, as the training notebook's target column implies.
_classes = list(getattr(model, "classes_", [0, 1]))
if _classes != [0, 1]:
    raise RuntimeError(f"unexpected class ordering {_classes}; expected [0, 1]")
PHISHING_INDEX = 1

FEATURE_IMPORTANCE = dict(zip(FEATURE_ORDER, model.feature_importances_))
# StandardScaler already carries the training mean and standard deviation for
# every column, so per-feature z-scores are available without touching the CSV.
FEATURE_MEAN = dict(zip(FEATURE_ORDER, scaler.mean_))
FEATURE_SCALE = dict(zip(FEATURE_ORDER, scaler.scale_))

_history: deque = deque(maxlen=500)
_history_lock = threading.Lock()

_email_history: deque = deque(maxlen=200)
_email_history_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

READABLE = {
    "directory_length": "Directory path length",
    "time_domain_activation": "Domain age (days)",
    "qty_dollar_directory": "'$' characters in path",
    "qty_dot_file": "'.' characters in filename",
    "qty_slash_directory": "'/' characters in path",
    "length_url": "Full URL length",
    "ttl_hostname": "DNS TTL (seconds)",
    "qty_percent_directory": "'%' characters in path",
    "asn_ip": "Host AS number",
    "time_response": "HTTP response time (s)",
    "qty_dot_url": "'.' characters in URL",
    "domain_length": "Domain length",
    "qty_hyphen_domain": "'-' characters in domain",
    "tls_ssl_certificate": "Valid TLS certificate",
    "qty_redirects": "Redirect count",
    "url_shortened": "Shortened URL",
    "qty_nameservers": "Nameserver count",
    "qty_mx_servers": "MX record count",
    "domain_in_ip": "Domain is a raw IP",
    "email_in_url": "Email address in URL",
}


def _label(name: str) -> str:
    return READABLE.get(name, name.replace("_", " ").capitalize())


def _zscore(name: str, value: float) -> float:
    scale = FEATURE_SCALE.get(name) or 1.0
    return (value - FEATURE_MEAN.get(name, 0.0)) / scale


def _risk_band(z: float) -> str:
    """
    Risk is how unusual the value is relative to the training distribution — a
    real, checkable quantity — rather than a hand-written judgement per feature.
    """
    magnitude = abs(z)
    if magnitude >= 2.0:
        return "high_risk"
    if magnitude >= 1.0:
        return "medium_risk"
    return "low_risk"


def _explain(named: dict[str, float]) -> dict[str, dict]:
    """
    Build the `features` block the frontend's impact panel renders. `impact` is
    the model's global importance for that feature, rescaled so the strongest
    feature in this response reads as 1.0. Values shown are the real extracted
    ones; -1 means the lookup was unavailable.
    """
    ranked = sorted(
        FEATURE_ORDER, key=lambda name: FEATURE_IMPORTANCE.get(name, 0.0), reverse=True
    )[:EXPLAIN_TOP_N]

    top_importance = max(FEATURE_IMPORTANCE.get(n, 0.0) for n in ranked) or 1.0
    block: dict[str, dict] = {}

    for name in ranked:
        value = named[name]
        z = _zscore(name, value)
        unavailable = value == -1
        block[name] = {
            "label": _label(name),
            "value": "unavailable" if unavailable else round(value, 4),
            # An unavailable lookup is not evidence of risk, so don't colour it as such.
            "risk": "low_risk" if unavailable else _risk_band(z),
            "impact": round(FEATURE_IMPORTANCE.get(name, 0.0) / top_importance, 4),
            "description": (
                f"{_label(name)} could not be determined for this host."
                if unavailable
                else f"{_label(name)} is {value:g}, "
                f"{abs(z):.1f} standard deviations "
                f"{'above' if z >= 0 else 'below'} the training average."
            ),
        }
    return block


def _verdict(p_phishing: float) -> tuple[str, float]:
    """
    Returns (verdict, confidence). Confidence is reported in the verdict given,
    which is what the UI's "Model Confidence" label means — so a Legitimate
    result reports 1 - P(phishing), not P(phishing).
    """
    if p_phishing >= PHISHING_THRESHOLD:
        return "Phishing", p_phishing
    if p_phishing <= LEGITIMATE_THRESHOLD:
        return "Legitimate", 1.0 - p_phishing
    # In the uncertain band, confidence in *either* label is low by definition.
    return "Suspicious", max(p_phishing, 1.0 - p_phishing)


def score_url(url: str, overrides: dict | None = None, with_network: bool = True) -> dict:
    # clip=True replicates the IQR bounds the training pipeline applied, so the
    # forest receives inputs from the same distribution it was fitted on.
    vector, named, clamped = extract_features(
        url, with_network=with_network, timeout=LOOKUP_TIMEOUT, overrides=overrides
    )
    scaled = scaler.transform(np.array([vector], dtype=float))
    p_phishing = float(model.predict_proba(scaled)[0][PHISHING_INDEX])
    prediction, confidence = _verdict(p_phishing)

    unavailable = [name for name in FEATURE_ORDER if named[name] == -1]

    return {
        "url": url,
        "prediction": prediction,
        "probability": round(confidence, 4),
        # Risk is always P(phishing), independent of which label was assigned,
        # so the gauge moves monotonically with danger.
        "risk_score": int(round(p_phishing * 100)),
        "phishing_probability": round(p_phishing, 4),
        "model": "Random Forest",
        "scan_id": f"scan_{uuid.uuid4().hex[:12]}",
        "scan_time": dt.datetime.now(dt.timezone.utc).isoformat(),
        "features": _explain(named),
        # Surfaced so the client can tell the user how complete the evidence was.
        "unavailable_features": len(unavailable),
        "total_features": len(FEATURE_ORDER),
        # Real measurements the training-time clipping forced the model to ignore.
        # A 140-character URL is reported to the model as 72; the user deserves to
        # know that happened rather than seeing a confident number.
        "clamped_features": clamped,
        "degenerate_features": list(DEGENERATE_FEATURES),
    }


def _record(result: dict) -> None:
    with _history_lock:
        _history.appendleft(
            {
                "id": result["scan_id"],
                "url": result["url"],
                "prediction": result["prediction"],
                "probability": result["probability"],
                "risk_score": result["risk_score"],
                "phishing_probability": result.get("phishing_probability"),
                "model": result["model"],
                "scan_time": result["scan_time"],
                "features": result.get("features", {}),
                "unavailable_features": result.get("unavailable_features", 0),
                "total_features": result.get("total_features", 0),
                "clamped_features": result.get("clamped_features", {}),
                "degenerate_features": result.get("degenerate_features", []),
            }
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
def index():
    """
    Root route:
    - If opened in a web browser, render the PhishGuard AI Backend Console & API Explorer.
    - If requested by an API client requesting JSON, return the API status and endpoints.
    """
    accept = request.headers.get("Accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return jsonify(
            {
                "status": "ok",
                "service": "PhishGuard AI Backend API",
                "version": "1.0.0",
                "web_app_url": "http://localhost:5173",
                "endpoints": {
                    "health": "/health",
                    "predict": "POST /predict",
                    "bulk_scan": "POST /bulk-scan",
                    "model_metrics": "/model-metrics",
                    "history": "/history",
                    "analytics": "/analytics",
                    "email_scan": "POST /api/email/scan",
                    "gmail_sync": "POST /api/email/gmail-sync",
                    "email_history": "/api/email/history",
                },
            }
        )

    return render_template("backend_console.html")


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "model": type(model).__name__,
            "n_estimators": getattr(model, "n_estimators", None),
            "features_expected": len(FEATURE_ORDER),
            "scaler_features": int(_expected),
            "training_clip_bounds": {k: list(v) for k, v in TRAINING_CLIP_BOUNDS.items()},
            "degenerate_features": list(DEGENERATE_FEATURES),
            "thresholds": {
                "phishing": PHISHING_THRESHOLD,
                "legitimate": LEGITIMATE_THRESHOLD,
            },
        }
    )


@app.post("/predict")
def predict():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"message": "A valid JSON object payload is required."}), 400

    raw_url = payload.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"message": "A 'url' string is required."}), 400

    url = raw_url.strip()
    if len(url) > 2048:
        return jsonify({"message": "URL exceeds maximum permitted length of 2048 characters."}), 400

    raw_overrides = payload.get("features")
    if raw_overrides is not None and not isinstance(raw_overrides, dict):
        return jsonify({"message": "'features' field must be an object/dict of feature overrides."}), 400

    overrides = {}
    if isinstance(raw_overrides, dict):
        for k, v in raw_overrides.items():
            if k in FEATURE_ORDER:
                try:
                    overrides[k] = float(v)
                except (ValueError, TypeError):
                    pass
        rejected = sorted(set(raw_overrides) - set(overrides))
    else:
        rejected = []

    try:
        result = score_url(url, overrides=overrides)
    except Exception as exc:  # noqa: BLE001 - surface the reason to the client
        app.logger.exception("prediction failed for %s", url)
        return jsonify({"message": f"Could not analyze that URL: {exc}"}), 500

    if rejected:
        result["ignored_features"] = rejected
    _record(result)
    return jsonify(result)


@app.post("/bulk-scan")
def bulk_scan():
    urls = []

    # 1. File Upload (multipart/form-data)
    if request.files and "file" in request.files:
        uploaded_file = request.files["file"]
        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"message": "No file selected for upload."}), 400

        filename = uploaded_file.filename.lower()
        if not (filename.endswith(".csv") or filename.endswith(".txt")):
            return jsonify({"message": "Unsupported file type. Only .csv and .txt files are allowed."}), 400

        content = uploaded_file.read()
        if len(content) == 0:
            return jsonify({"message": "Uploaded file is empty."}), 400
        if len(content) > 2 * 1024 * 1024:  # 2MB limit
            return jsonify({"message": "File size exceeds 2MB limit."}), 413

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return jsonify({"message": "Could not decode file content as UTF-8."}), 400

        if filename.endswith(".csv"):
            import csv
            import io
            reader = csv.reader(io.StringIO(text))
            rows = [r for r in reader if r and any(cell.strip() for cell in r)]
            if not rows:
                return jsonify({"message": "CSV file contains no readable data."}), 400

            # Auto-detect URL column header if present
            url_col_idx = 0
            header_found = False
            for col_idx, cell in enumerate(rows[0]):
                if cell.lower().strip() in {"url", "urls", "domain", "link", "website"}:
                    url_col_idx = col_idx
                    header_found = True
                    break

            start_row = 1 if header_found else 0
            for r in rows[start_row:]:
                if len(r) > url_col_idx and r[url_col_idx].strip():
                    urls.append(r[url_col_idx].strip())
        else:
            # .txt file: one URL per line
            for line in text.splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    urls.append(cleaned)

        # Deduplicate while preserving order
        urls = list(dict.fromkeys(urls))
        if not urls:
            return jsonify({"message": "No valid URLs found in uploaded file."}), 400

    # 2. JSON Body ({ "urls": [...] })
    else:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"message": "A JSON payload or file upload is required."}), 400
        raw_urls = payload.get("urls")
        if not isinstance(raw_urls, list) or not raw_urls:
            return jsonify({"message": "A non-empty 'urls' array is required."}), 400

        urls = [str(u).strip() for u in raw_urls if str(u).strip()]
        urls = list(dict.fromkeys(urls))
        if not urls:
            return jsonify({"message": "A non-empty 'urls' array is required."}), 400

    if len(urls) > BULK_MAX_URLS:
        return jsonify({"message": f"At most {BULK_MAX_URLS} URLs per request."}), 413

    def safe(url: str):
        try:
            return score_url(url)
        except Exception as exc:  # noqa: BLE001
            return {"url": url, "error": str(exc), "prediction": "Error", "risk_score": 0}

    # Network lookups dominate the runtime and are IO-bound, so threads help.
    with ThreadPoolExecutor(max_workers=BULK_WORKERS) as pool:
        results = list(pool.map(safe, urls))

    for result in results:
        if "error" not in result:
            _record(result)
    return jsonify(results)


@app.get("/model-metrics")
def model_metrics():
    """
    Figures from notebook/model_building.ipynb. Only the Random Forest is loaded
    here; the other two rows are its recorded comparison baselines.
    """
    training_samples = 69767
    confusion = {"truePositive": 5850, "falsePositive": 273, "trueNegative": 11070, "falseNegative": 249}
    ranked = sorted(
        FEATURE_IMPORTANCE.items(), key=lambda item: item[1], reverse=True
    )[:10]

    return jsonify(
        {
            "models": [
                {
                    "name": "Random Forest",
                    "selected": True,
                    "hyperparameters": f"n_estimators={getattr(model, 'n_estimators', 100)}, random_state=42",
                    "accuracy": 0.9701,
                    "precision": 0.9554,
                    "recall": 0.9592,
                    "f1_score": 0.9573,
                    "roc_auc": 0.995,
                    "training_samples": training_samples,
                    "description": "Ensemble learning method using multiple decision trees for robust phishing classification.",
                },
                {
                    "name": "Decision Tree",
                    "selected": False,
                    "hyperparameters": "random_state=42, unpruned",
                    "accuracy": 0.9504,
                    "precision": 0.9327,
                    "recall": 0.9249,
                    "f1_score": 0.9288,
                    "roc_auc": 0.9445,
                    "training_samples": training_samples,
                    "description": "Tree-based classifier that splits data using feature thresholds for interpretable predictions.",
                },
                {
                    "name": "Logistic Regression",
                    "selected": False,
                    "hyperparameters": "max_iter=1000",
                    "accuracy": 0.9293,
                    "precision": 0.8902,
                    "recall": 0.9101,
                    "f1_score": 0.9,
                    "roc_auc": 0.9778,
                    "training_samples": training_samples,
                    "description": "Linear model that estimates phishing probability using a logistic function.",
                },
            ],
            # Read live off the loaded model, so this can never drift from it.
            "featureImportance": [
                {
                    "feature": _label(name),
                    "key": name,
                    "importance": round(float(importance), 4),
                    "category": "Network"
                    if name
                    in {
                        "ttl_hostname",
                        "asn_ip",
                        "time_response",
                        "qty_nameservers",
                        "qty_mx_servers",
                        "domain_spf",
                    }
                    else "Domain"
                    if "domain" in name
                    else "URL Structure",
                }
                for name, importance in ranked
            ],
            "comparisonData": [
                {"metric": "Accuracy", "Logistic Regression": 92.93, "Decision Tree": 95.04, "Random Forest": 97.01},
                {"metric": "Precision", "Logistic Regression": 89.02, "Decision Tree": 93.27, "Random Forest": 95.54},
                {"metric": "Recall", "Logistic Regression": 91.01, "Decision Tree": 92.49, "Random Forest": 95.92},
                {"metric": "F1 Score", "Logistic Regression": 90.0, "Decision Tree": 92.88, "Random Forest": 95.73},
                {"metric": "ROC-AUC", "Logistic Regression": 97.78, "Decision Tree": 94.45, "Random Forest": 99.5},
            ],
            "testSamples": 17442,
            "confusion": confusion,
            "falsePositiveRate": round(
                confusion["falsePositive"] / (confusion["falsePositive"] + confusion["trueNegative"]) * 100, 2
            ),
            "falseNegativeRate": round(
                confusion["falseNegative"] / (confusion["falseNegative"] + confusion["truePositive"]) * 100, 2
            ),
        }
    )


@app.get("/history")
def history():
    with _history_lock:
        return jsonify(list(_history))


@app.get("/analytics")
def analytics():
    """
    Real aggregates over scans this process has performed. Starts empty — that is
    correct, not a bug. It fills as URLs are scanned.
    """
    with _history_lock:
        scans = list(_history)

    counts = Counter(s["prediction"] for s in scans)
    legitimate = counts.get("Legitimate", 0)
    suspicious = counts.get("Suspicious", 0)
    phishing = counts.get("Phishing", 0)
    total = legitimate + suspicious + phishing

    by_day: Counter = Counter()
    for scan in scans:
        by_day[scan["scan_time"][:10]] += 1

    buckets = [
        {
            "time": day,
            "total": count,
            "legitimate": sum(
                1 for s in scans if s["scan_time"][:10] == day and s["prediction"] == "Legitimate"
            ),
            "suspicious": sum(
                1 for s in scans if s["scan_time"][:10] == day and s["prediction"] == "Suspicious"
            ),
            "phishing": sum(
                1 for s in scans if s["scan_time"][:10] == day and s["prediction"] == "Phishing"
            ),
        }
        for day, count in sorted(by_day.items())
    ]

    return jsonify(
        {
            "totalScans": total,
            "phishingDetected": phishing,
            "legitimateWebsites": legitimate,
            "modelAccuracy": 97.01,
            "totalScansChange": 0,
            "phishingChange": 0,
            "legitimateChange": 0,
            "accuracyChange": 0,
            # Same buckets for every range: this process has one session's worth
            # of data, so pretending to slice it by 24H/7D/30D/90D would be fiction.
            "detectionActivity": {key: buckets for key in ("24H", "7D", "30D", "90D")},
            "riskDistribution": [
                {"name": "Safe", "value": legitimate},
                {"name": "Suspicious", "value": suspicious},
                {"name": "Phishing", "value": phishing},
            ],
            "detectionTrends": [
                {
                    "month": bucket["time"],
                    "legitimate": bucket["legitimate"],
                    "suspicious": bucket["suspicious"],
                    "phishing": bucket["phishing"],
                }
                for bucket in buckets
            ],
            "scanActivity": [{"day": bucket["time"], "scans": bucket["total"]} for bucket in buckets],
            # Would require brand-impersonation detection, which this model does
            # not do. Empty rather than invented.
            "topTargetedBrands": [],
        }
    )


# ---------------------------------------------------------------------------
# Email & Gmail Threat Scanner Routes
# ---------------------------------------------------------------------------

def _score_url_for_email(url: str) -> dict:
    try:
        return score_url(url, with_network=False)
    except Exception as exc:
        return {
            "url": url,
            "prediction": "Unknown",
            "phishing_probability": 0.3,
            "risk_score": 30,
            "error": str(exc)
        }


@app.get("/api/email/presets")
@app.get("/email/presets")
def email_presets():
    return jsonify(email_scanner.PRESET_EMAILS)


@app.post("/api/email/scan")
@app.post("/email/scan")
def scan_email():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"message": "A valid JSON object payload is required."}), 400
    raw_content = payload.get("raw_content", "")
    subject = payload.get("subject", "")
    sender = payload.get("sender", "")
    body = payload.get("body", "")

    if not raw_content and not body and not subject:
        return jsonify({"message": "Please provide email content, subject, or body to analyze."}), 400

    try:
        report = email_scanner.evaluate_email_threat(
            raw_content=raw_content,
            subject=subject,
            sender=sender,
            body=body,
            predict_fn=_score_url_for_email
        )
    except Exception as exc:
        app.logger.exception("Email threat analysis failed")
        return jsonify({"message": f"Failed to analyze email: {exc}"}), 500

    with _email_history_lock:
        _email_history.appendleft({
            "scan_id": report["scan_id"],
            "scan_time": report["scan_time"],
            "subject": report["subject"] or "(No subject)",
            "sender": report["sender"] or "(Unknown sender)",
            "verdict": report["verdict"],
            "risk_score": report["risk_score"],
            "threat_level": report["threat_level"],
            "theme": report["theme"]
        })

    return jsonify(report)


@app.get("/api/email/history")
@app.get("/email/history")
def email_history():
    with _email_history_lock:
        return jsonify(list(_email_history))


@app.post("/api/email/gmail-sync")
@app.post("/email/gmail-sync")
def gmail_sync():
    """
    Syncs and scans messages from Gmail.
    Supports:
    1. Direct Gmail IMAP: email + 16-character App Password (recommended, works instantly)
    2. Google OAuth: Bearer access_token
    3. Demo / Sandbox mode: instant realistic attack simulation
    """
    payload = request.get_json(silent=True) or {}
    user_email = (payload.get("email") or "").strip()
    app_pwd = (payload.get("app_password") or "").strip()
    token = (payload.get("access_token") or "").strip()
    
    scanned_emails = []
    mode = "sandbox_demo"

    if user_email and app_pwd:
        # 1. Direct IMAP Sync
        try:
            scanned_emails = email_scanner.fetch_gmail_via_imap(
                user_email=user_email,
                app_password=app_pwd,
                max_emails=8,
                predict_fn=_score_url_for_email
            )
            mode = "live_imap"
        except Exception as exc:
            app.logger.warning("Gmail IMAP error: %s", exc)
            return jsonify({"message": str(exc)}), 400

    elif token:
        # 2. OAuth2 Sync
        import requests
        try:
            headers = {"Authorization": f"Bearer {token}"}
            list_res = requests.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=8",
                headers=headers,
                timeout=10
            )
            if list_res.status_code != 200:
                return jsonify({
                    "message": "Gmail API authentication failed. Verify token or refresh credentials.",
                    "details": list_res.text
                }), 401
                
            msg_list = list_res.json().get("messages", [])
            for item in msg_list:
                msg_id = item.get("id")
                detail_res = requests.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full",
                    headers=headers,
                    timeout=10
                )
                if detail_res.status_code == 200:
                    data = detail_res.json()
                    headers_list = data.get("payload", {}).get("headers", [])
                    subj = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "")
                    sender_hdr = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "")
                    snippet = data.get("snippet", "")
                    
                    report = email_scanner.evaluate_email_threat(
                        subject=subj,
                        sender=sender_hdr,
                        body=snippet,
                        predict_fn=_score_url_for_email
                    )
                    report["gmail_id"] = msg_id
                    scanned_emails.append(report)
            mode = "live_oauth"
        except Exception as exc:
            app.logger.exception("Gmail sync error")
            return jsonify({"message": f"Gmail synchronization failed: {exc}"}), 500
    else:
        # Sandbox / Demo sync mode
        for preset in email_scanner.PRESET_EMAILS:
            report = email_scanner.evaluate_email_threat(
                subject=preset["subject"],
                sender=preset["sender"],
                body=preset["body"],
                predict_fn=_score_url_for_email
            )
            report["preset_id"] = preset["id"]
            report["preset_title"] = preset["title"]
            scanned_emails.append(report)

    # Record into history
    with _email_history_lock:
        for rep in scanned_emails:
            _email_history.appendleft({
                "scan_id": rep["scan_id"],
                "scan_time": rep["scan_time"],
                "subject": rep["subject"] or "(No subject)",
                "sender": rep["sender"] or "(Unknown sender)",
                "verdict": rep["verdict"],
                "risk_score": rep["risk_score"],
                "threat_level": rep["threat_level"],
                "theme": rep["theme"]
            })

    return jsonify({
        "status": "success",
        "mode": mode,
        "total_scanned": len(scanned_emails),
        "results": scanned_emails
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
