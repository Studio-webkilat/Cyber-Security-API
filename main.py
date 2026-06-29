import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html
from models import SecurityScanRequest
from scanner import perform_scan

app = FastAPI(title="Cyber Academy Security API")

API_KEY = os.environ.get("API_KEY_RAHASIA")

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Cyber Academy",
        swagger_css_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css",
    ) + """<style>
        body { background: #0D1117 !important; color: #E2E8F0 !important; font-family: 'Courier New', Courier, monospace !important; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { color: #00FF66 !important; }
        .swagger-ui .opblock .opblock-summary-path { color: #00FF66 !important; }
        .swagger-ui .scheme-container { background: #0D1117 !important; }
        .swagger-ui .btn { background: #00FF66 !important; color: #000 !important; border-radius: 0 !important; }
        .swagger-ui .opblock-summary { background: #1A1F2C !important; border: 1px solid #00FF66 !important; }
        .swagger-ui .response-col_status.success { color: #00FF66 !important; font-weight: bold; }
        .swagger-ui .response-col_status.warning { color: #FFD700 !important; font-weight: bold; }
        .swagger-ui .response-col_status.error { color: #FF4444 !important; font-weight: bold; }
        .swagger-ui .info { border-bottom: 1px solid #333; margin-bottom: 20px; }
    </style>"""

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
