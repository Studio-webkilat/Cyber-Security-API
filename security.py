# Tambahin import ini di atas
from sqlalchemy.orm import Session
from database import SessionLocal 
from models import HackingLog

# Ganti fungsi log_attack jadi gini
def log_attack(request: Request, status_code: int):
    client_ip = request.client.host
    if client_ip in BLACKLIST: return
        
    # 1. INSERT KE DB NEON
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

    # 2. LOGIC AUTO-BAN
    now = time.time()
    ip_attempts[client_ip].append(now)
    ip_attempts[client_ip] = [t for t in ip_attempts[client_ip] if now - t < BAN_WINDOW_SECONDS]
    if len(ip_attempts[client_ip]) >= BAN_THRESHOLD:
        BLACKLIST.add(client_ip)
        print(f"[ALERT] IP {client_ip} DIBAN OTOMATIS")