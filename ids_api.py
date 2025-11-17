from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import joblib
import pandas as pd
import numpy as np

app = FastAPI(title="SDN IDS API", version="0.1")

# ---------- Pydantic model: what ONOS (or client) sends ----------
class Flow(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    byte_count: Optional[float] = 0.0
    packet_count: Optional[float] = 0.0
    duration_sec: Optional[float] = 0.0

# ---------- Load trained objects on startup ----------
@app.on_event("startup")
def load_artifacts():
    global scaler, rf, numeric_cols, label_enc

    scaler = joblib.load("scaler.joblib")
    rf = joblib.load("rf_model.joblib")
    numeric_cols = joblib.load("numeric_cols.joblib")
    label_enc = joblib.load("label_encoder.joblib")

    print("Loaded artifacts:")
    print(" - numeric_cols:", numeric_cols)
    print(" - classes:", list(label_enc.classes_))


# ---------- Helper to build feature row (same logic as poll script) ----------
def build_feature_row(flow: Flow) -> dict:
    duration = flow.duration_sec or 0.0
    pkts = flow.packet_count or 0.0
    bytes_ = flow.byte_count or 0.0

    if duration > 0:
        pkts_s = pkts / duration
        bytes_s = bytes_ / duration
    else:
        pkts_s = 0.0
        bytes_s = 0.0

    # This must match what you used during training
    return {
        "Flow Duration": duration,
        "Tot Fwd Pkts": pkts,
        "Tot Bwd Pkts": 0.0,          # unknown direction -> 0
        "TotLen Fwd Pkts": bytes_,
        "TotLen Bwd Pkts": 0.0,
        "Flow Byts/s": bytes_s,
        "Flow Pkts/s": pkts_s,
    }


# ----- Main endpoint -----
@app.post("/predict")
def predict_flow(flow: Flow):
    print("Received flow:", flow)

    # 1. Build one row of features
    row = build_feature_row(flow)

    # 2. Put into DataFrame and select the same numeric_cols as in training
    X_raw = pd.DataFrame([row])[numeric_cols].astype(float)

    # 3. Scale
    # scaler.transform returns a numpy array, which causes the UserWarning
    X_scaled_array = scaler.transform(X_raw)

    # Convert back to DataFrame to preserve feature names and silence the warning
    # The columns are guaranteed to be in the correct order because X_raw already was.
    X_scaled_df = pd.DataFrame(X_scaled_array, columns=numeric_cols)

    # 4. Predict
    y_pred = rf.predict(X_scaled_df)
    label = label_enc.inverse_transform(y_pred.astype(int))[0]

    print("Label: ", label)

    # 5. Optional: probability / confidence
    confidence = None
    if hasattr(rf, "predict_proba"):
        proba_vec = rf.predict_proba(X_scaled_df)[0]
        confidence = float(np.max(proba_vec))

    # 6. Decide if this label means attack
    NORMAL_CANDIDATES = {"BENIGN", "Benign", "benign", "NORMAL", "Normal", "normal"}
    is_attack = label not in NORMAL_CANDIDATES

    return {
        "label": label,
        "is_attack": is_attack,
        "confidence": confidence,
        "features_used": row,  # optional, handy for debugging
    }
