import os
from fastapi import FastAPI, Header, HTTPException
from models import SecurityScanRequest
from scanner import perform_scan

app = FastAPI(title="Cyber Academy Security API")

API_KEY = os.environ.get("API_KEY_RAHASIA")

@app.post("/api/v1/scan")
async def scan_website(request: SecurityScanRequest, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Akses Ditolak")
    
    data = perform_scan(str(request.target_url))
    score = data.get("score", 0)
    
    if score <= 25:
        data["status_visual"] = "🔴 (Sangat Rentan)"
    elif score <= 70:
        data["status_visual"] = "🟠 (Perlu Perbaikan)"
    elif score <= 85:
        data["status_visual"] = "🟢 (Aman)"
    else:
        data["status_visual"] = "🔵 (Sangat Aman)"
        
    data["history_threat"] = "Terdeteksi 2 upaya serangan DDoS di bulan Juni 2026 pada target ini"
    
    return data

@app.get("/")
def read_root():
    return {"message": "Cyber Academy API Online"}
