from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bson import ObjectId, json_util
from .services.pipeline import process_job
from .db.mongo import jobs, mongo_client
from fastapi.responses import JSONResponse
import json

app = FastAPI(title="autopitch-worker")

class RunPayload(BaseModel):
    jobId: str
    obsKey: str

@app.get("/health")
def health():
    return {"ok": True, "service": "worker"}


@app.get("/db/ping")
async def db_ping():
    try:
        res = await mongo_client.admin.command("ping")
        payload = {"ok": True, "mongo": res}
        return JSONResponse(content=json.loads(json_util.dumps(payload)))
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

@app.post("/run")
async def run_job(payload: RunPayload):
    oid = None
    try:
        oid = ObjectId(payload.jobId)
    except Exception:
        raise HTTPException(400, "invalid jobId")
    doc = await jobs.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "job not found")

    await process_job(oid, payload.obsKey)
    return {"ok": True}


@app.on_event("shutdown")
async def shutdown_db():
    try:
        mongo_client.close()
    except Exception:
        pass
