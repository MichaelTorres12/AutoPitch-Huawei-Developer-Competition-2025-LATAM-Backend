from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .db.mongo import mongo_client, jobs
from .routers import jobs as jobs_router
from .routers import uploads as uploads_router
from .routers import pitches as pitches_router
from .routers import cloud as cloud_router
from .routers import obs_sign as obs_sign_router
from fastapi.responses import JSONResponse
import json
from bson import json_util

app = FastAPI(title="autopitch-orchestrator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.CORS_ORIGIN] if settings.CORS_ORIGIN != "*" else ["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"ok": True, "service": "orchestrator"}

@app.get("/db/ping")
async def db_ping():
    try:
        res = await mongo_client.admin.command("ping")
        payload = {"ok": True, "mongo": res}
        # Use bson.json_util to handle special BSON types (e.g., Timestamp)
        return JSONResponse(content=json.loads(json_util.dumps(payload)))
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

# índices mínimos
@app.on_event("startup")
async def init_db():
    try:
        await mongo_client.admin.command("ping")
        # Jobs collection indices
        await jobs.create_index([( "status", 1 ), ( "created_at", 1 )])
        await jobs.create_index([( "created_at", -1 )])
        # Pitches collection indices
        pitches = mongo_client.get_default_database()["pitches"]
        await pitches.create_index([( "status", 1 ), ( "created_at", 1 )])
        await pitches.create_index([( "created_at", -1 )])
        await pitches.create_index([( "uploadId", 1 )])
    except Exception as e:
        print("DB init error:", e)

app.include_router(jobs_router.router)
app.include_router(uploads_router.router)
app.include_router(pitches_router.router)
app.include_router(cloud_router.router)
app.include_router(obs_sign_router.router)

app.include_router(cloud_router.router, prefix="/cloud", tags=["cloud"])

@app.on_event("shutdown")
async def shutdown_db():
    try:
        mongo_client.close()
    except Exception:
        pass