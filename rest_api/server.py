from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="SDN IDS API", version="0.1")

# ----- Define what ONOS will send -----
class Flow(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    byte_count: Optional[int] = None
    packet_count: Optional[int] = None
    duration_sec: Optional[float] = None
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

# ----- Main endpoint -----
@app.post("/predict")
def predict_flow(flow: Flow):

    print("Received flow:", flow)

    # --- Placeholder logic ---
    label = "normal"

    if (flow.packet_count and flow.packet_count > 1000):
    #if (flow.src_ip or flow.eth_src or (flow.packet_count and flow.packet_count > 160000)):
        label = "DoS"

    return {"label": label}

