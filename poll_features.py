import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import time

ONOS_URL = "http://192.168.32.77:8181"
AUTH = HTTPBasicAuth("onos", "rocks")   # change if you use other creds

def fetch_flows():
    url = f"{ONOS_URL}/onos/v1/flows"
    r = requests.get(url, auth=AUTH)
    r.raise_for_status()
    return r.json()["flows"]

def extract_features_from_flow(flow):
    """
    Take a single ONOS flow dict and return the features your model needs.
    """
    # Duration: some ONOS versions use 'life', others 'durationSeconds'
    duration = flow.get("life")
    if duration is None:
        duration = flow.get("durationSeconds", 0)

    packets = flow.get("packets", 0)
    bytes_ = flow.get("bytes", 0)

    # Avoid division by zero
    if not duration or duration <= 0:
        flow_pkts_s = 0.0
        flow_byts_s = 0.0
    else:
        flow_pkts_s = packets / duration
        flow_byts_s = bytes_ / duration

    # For now, treat each ONOS flow as "forward" only
    tot_fwd_pkts = packets
    totlen_fwd_pkts = bytes_

    # We don't have backward direction yet → set to 0
    tot_bwd_pkts = 0
    totlen_bwd_pkts = 0

    return {
        "Flow ID": flow.get("id"),
        "Device": flow.get("deviceId"),

        # Features used by your RF model:
        "Flow Duration": duration,
        "Tot Fwd Pkts": tot_fwd_pkts,
        "Tot Bwd Pkts": tot_bwd_pkts,
        "TotLen Fwd Pkts": totlen_fwd_pkts,
        "TotLen Bwd Pkts": totlen_bwd_pkts,
        "Flow Byts/s": flow_byts_s,
        "Flow Pkts/s": flow_pkts_s,
    }

def poll_once():
    flows = fetch_flows()
    rows = [extract_features_from_flow(f) for f in flows]
    df = pd.DataFrame(rows)
    return df

if __name__ == "__main__":
    while True:
        try:
            df = poll_once()
            print("\n=== Polled features ===")
            print(df.head())   # only first few rows
        except Exception as e:
            print("Error polling ONOS:", e)
        time.sleep(3)          # poll every 3 seconds
