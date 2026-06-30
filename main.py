from fastapi import FastAPI, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import HTMLResponse

from database import engine, get_db, Base
from models import HackingLog
from security import CyberSecurityMiddleware, AuditLoggerMiddleware, verify_jwt, get_admin_user

# Custom Swagger UI CSS + JS dari Gemini
custom_css = """<style> :root{--neon-green:#00FF88;--neon-magenta:#FF00FF;--neon-cyan:#00E5FF;--dark-bg:#0D1117;} body{background-color:var(--dark-bg)!important;font-family:'Courier New',monospace!important;}.swagger-ui.topbar{display:none;}.swagger-ui.info.title{color:var(--neon-green)!important;text-shadow:0 0 10px var(--neon-green);}.swagger-ui.btn{border:1px solid var(--neon-green)!important;color:var(--neon-green)!important;box-shadow:0 0 5px var(--neon-green)!important;}.swagger-ui.btn:hover{background:var(--neon-magenta)!important;animation:glitch.2s linear infinite;} @keyframes glitch{20%{transform:translate(-2px,2px)}40%{transform:translate(-2px,-2px)}}.swagger-ui.prism-code.token.key{color:var(--neon-magenta)!important;}.swagger-ui.prism-code.token.string{color:var(--neon-green)!important;}.swagger-ui.prism-code.token.number{color:var(--neon-cyan)!important;} body::before{content:" ";position:fixed;top:0;left:0;right:0;bottom:0;background:linear-gradient(rgba(18,16,16,0)50%,rgba(0,0,0,0.25)50%);background-size:100% 4px;pointer-events:none;z-index:9999;}</style>"""

app = FastAPI(docs_url="/docs", redoc_url=None)

# === MIDDLEWARE STACK ===
app.add_middleware(CyberSecurityMiddleware)
app.add_middleware(AuditLoggerMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

# === RATE LIMIT ===
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# === LOGIC BACKGROUND TASK ===
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    response = await call_next(request)
    if hasattr(request.state, "log_data"):
        req, status = request.state.log_data
        log_attack(req, status) # Panggil fungsi dari security.py
    return response

# === ROUTES ===
@app.get("/secure-scan", dependencies=[Depends(limiter.limit("5/minute"))])
async def secure_scan(user: dict = Depends(verify_jwt)):
    return {"message": "Akses Diterima, Agent."}

@app.get("/admin/logs")
async def get_hacking_logs(admin: dict = Depends(get_admin_user), db = Depends(get_db)):
    return db.query(HackingLog).order_by(HackingLog.timestamp.desc()).limit(100).all()

@app.get("/status")
def status():
    return {"status": "ONLINE", "system": "Cyber-Academy-Kernel-v1.0"}