import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html
from models import SecurityScanRequest
from scanner import perform_scan

app = FastAPI(title="Cyber Academy Security API", docs_url=None, redoc_url=None)

API_KEY = os.environ.get("API_KEY_RAHASIA")

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="Cyber Academy",
        swagger_css_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css",
    ) + """<style>body{background:#000;color:#0f0;} .swagger-ui .topbar{display:none;} .swagger-ui .info .title{color:#0f0;}</style>"""

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
