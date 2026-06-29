from fastapi import APIRouter
from models import SecurityScanRequest, SecurityResponse
import requests

router = APIRouter()

@router.post("/scan", response_model=SecurityResponse)
async def run_security_scan(request: SecurityScanRequest):
    target = str(request.target_url)
    
    try:
        response = requests.get(target, timeout=5)
        headers = response.headers
        
        
        security_config = {
            'Content-Security-Policy': "Mencegah serangan XSS.",
            'X-Frame-Options': "Mencegah Clickjacking.",
            'X-Content-Type-Options': "Mencegah MIME-type sniffing.",
            'Strict-Transport-Security': "Mewajibkan koneksi HTTPS."
        }
        
        results = {}
        missing = []
        
        for header, description in security_config.items():
            if header in headers:
                results[header] = "Pass"
            else:
                results[header] = "Missing"
                missing.append(description)
        
        
        score = sum(1 for v in results.values() if v == "Pass") * 25
        
        return {
            "status": "success",
            "message": f"Scan selesai untuk {target}",
            "data": {
                "score": score,
                "details": results,
                "recommendations": missing
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Gagal memindai target: {str(e)}",
            "data": {}
        }
