import time
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import joblib
import numpy as np

# ---------- ONOS connection ----------
ONOS_URL = "http://192.168.32.77:8181"
AUTH = HTTPBasicAuth("onos", "rocks")  # change if needed

# ---------- Load trained objects ----------
scaler = joblib.load("scaler.joblib")
rf = joblib.load("rf_model.joblib")
numeric_cols = joblib.load("numeric_cols.joblib")
label_enc = joblib.load("label_encoder.joblib")

# Optionally inspect classes:
# print("Model classes:", label_enc.classes_)

# ---------- Polling helpers ----------

def fetch_flows():
    url = f"{ONOS_URL}/onos/v1/flows"
    r = requests.get(url, auth=AUTH)
    r.raise_for_status()
    return r.json()["flows"]

def extract_features_from_flow(flow):
    """Build one row of features, same names as in numeric_cols."""
    duration = flow.get("life") or flow.get("durationSeconds", 0)
    pkts = flow.get("packets", 0)
    bytes_ = flow.get("bytes", 0)

    if duration and duration > 0:
        pkts_s = pkts / duration
        bytes_s = bytes_ / duration
    else:
        pkts_s = 0.0
        bytes_s = 0.0

    # We treat ONOS per-rule stats as "forward" direction for now
    return {
        "Flow ID": flow.get("id"),
        "Device": flow.get("deviceId"),

        # ML features (must match numeric_cols)
        "Flow Duration": duration,
        "Tot Fwd Pkts": pkts,
        "Tot Bwd Pkts": 0,          # we don't have direction split yet
        "TotLen Fwd Pkts": bytes_,
        "TotLen Bwd Pkts": 0,
        "Flow Byts/s": bytes_s,
        "Flow Pkts/s": pkts_s,
    }

def poll_df():
    flows = fetch_flows()
    rows = [extract_features_from_flow(f) for f in flows]
    return pd.DataFrame(rows)

# ---------- IDS main loop ----------

def main():
    print("Starting IDS loop (Ctrl+C to stop)...")

    while True:
        df = poll_df()

        if df.empty:
            print("No flows in ONOS at the moment.")
            time.sleep(2)
            continue

        # 1. Select the same numeric columns as in training
        X_raw = df[numeric_cols].astype(float)

        # 2. Apply the trained scaler
        X_scaled = scaler.transform(X_raw)

        # 3. Run the trained RF model
        y_pred = rf.predict(X_scaled)

        # 4. Convert numeric predictions back to original label names
        labels = label_enc.inverse_transform(y_pred.astype(int))

        df["Pred_Label"] = labels

        # 5. Decide overall network state
        # (adjust this if your positive class name is different)
        # e.g. if label_enc.classes_ is ['BENIGN', 'ATTACK']
        if any(lbl != label_enc.classes_[3] for lbl in labels):
            # assume first class is "normal", everything else is attack
            network_state = "⚠️ UNDER ATTACK"
        else:
            network_state = "✅ NORMAL"

        print("\n=== IDS Snapshot ===")
        print(df[["Flow ID", "Device"] + numeric_cols + ["Pred_Label"]].head())
        print(f"Network state: {network_state} "
              f"(flows: {len(df)}, attacks: {(df['Pred_Label'] != label_enc.classes_[0]).sum()})")

        time.sleep(2)

if __name__ == "__main__":
    main()
