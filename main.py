from fastapi import FastAPI, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from database import engine, get_db, Base
from models import HackingLog
from security import CyberSecurityMiddleware, AuditLoggerMiddleware, verify_jwt, get_admin_user

# Pastikan selector CSS punya spasi agar terbaca oleh browser
custom_css = """<style> 
:root{--neon-green:#00FF88;--neon-magenta:#FF00FF;--neon-cyan:#00E5FF;--dark-bg:#0D1117;} 
body{background-color:var(--dark-bg)!important;font-family:'Courier New',monospace!important;}
.swagger-ui .topbar{display:none;}
.swagger-ui .info .title{color:var(--neon-green)!important;text-shadow:0 0 10px var(--neon-green);}
.swagger-ui .btn{border:1px solid var(--neon-green)!important;color:var(--neon-green)!important;box-shadow:0 0 5px var(--neon-green)!important;}
.swagger-ui .btn:hover{background:var(--neon-magenta)!important;animation:glitch .2s linear infinite;}
@keyframes glitch{20%{transform:translate(-2px,2px)}40%{transform:translate(-2px,-2px)}}
.swagger-ui .prism-code .token.key{color:var(--neon-magenta)!important;}
.swagger-ui .prism-code .token.string{color:var(--neon-green)!important;}
.swagger-ui .prism-code .token.number{color:var(--neon-cyan)!important;}
</style>"""

Base.metadata.create_all(bind=engine)

app = FastAPI(docs_url=None, redoc_url=None) # Disable default docs


app.add_middleware(CyberSecurityMiddleware)
app.add_middleware(AuditLoggerMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    response = get_swagger_ui_html(openapi_url="/openapi.json", title="Cyber Academy")
    html_content = response.body.decode("utf-8")
    return HTMLResponse(content=html_content.replace("</head>", f"{custom_css}\n</head>"))

@app.get("/admin/logs")
async def get_hacking_logs(admin: dict = Depends(get_admin_user), db = Depends(get_db)):
    return db.query(HackingLog).order_by(HackingLog.timestamp.desc()).limit(100).all()
