from fastapi import Request, Depends, HTTPException, status, Response 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal
from models import HackingLog
from collections import defaultdict
import time
from jose import JWTError, jwt 

# === VAR GLOBAL ===
BLACKLIST = set() 
ip_attempts = defaultdict(list)
SECRET_KEY = "cyber-secret-key-ganti-nanti" # Ganti di production
ALGORITHM = "HS256"
security = HTTPBearer()

# === 1. LOGIC BAN & LOG ===
def log_attack(request: Request, status_code: int):
    client_ip = request.client.host
    if client_ip in BLACKLIST: 
        return

    db: Session = SessionLocal()
    try:
        new_log = HackingLog(
            ip_address=client_ip,
            endpoint=request.url.path,
            status_code=status_code,
            user_agent=request.headers.get("user-agent")
        )
        db.add(new_log)
        db.commit()
    finally:
        db.close()

    now = time.time()
    ip_attempts[client_ip].append(now)
    ip_attempts[client_ip] = [t for t in ip_attempts[client_ip] if now - t < 60]
    if len(ip_attempts[client_ip]) > 10: # >10 request per 60 detik = BAN
        BLACKLIST.add(client_ip)

# === 2. MIDDLEWARE ===
class AuditLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        log_attack(request, response.status_code)
        return response

class CyberSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        if client_ip in BLACKLIST:
            return Response("IP Banned", status_code=403) # <- INI YANG BUTUH IMPORT Response
        return await call_next(request)

# === 3. AUTH JWT ===
def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

def get_admin_user(payload: dict = Depends(verify_jwt)):
    if payload.get("role")!= "admin":
        raise HTTPException(status_code=403, detail="Not an admin")
    return payload