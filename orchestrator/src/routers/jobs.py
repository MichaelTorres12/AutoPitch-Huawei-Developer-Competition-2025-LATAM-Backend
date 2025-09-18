from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone
from bson import ObjectId
from ..db.mongo import db
from ..models.schemas import JobIn, JobDB, JobOut
from ..services.obs_sign import presign_put, presign_get_artifact, object_exists_in_uploads


router = APIRouter(prefix="/api", tags=["jobs"])
COL = db["jobs"]


@router.post("/jobs")
async def create_job(payload: JobIn):
    job = JobDB(
        status="uploading",
        goal=payload.goal,
        tone=payload.tone,
        slides=payload.slides,
    )
    job.obs_key = f"videos/{job.id}.mp4"
    await COL.insert_one(job.model_dump(by_alias=True))
    upload_url = presign_put(job.obs_key)
    return {"jobId": str(job.id), "uploadUrl": upload_url}


@router.patch("/jobs/{job_id}/uploaded")
async def mark_uploaded(job_id: str):
    doc = await COL.find_one({"_id": ObjectId(job_id)})
    if not doc:
        raise HTTPException(404, "Job not found")
    key = doc.get("obs_key")
    if not key:
        raise HTTPException(400, "Job has no obs_key")

    if not object_exists_in_uploads(key):
        raise HTTPException(400, "OBS object not found yet")

    await COL.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "uploaded", "updated_at": datetime.now(timezone.utc)}}
    )
    return {"ok": True}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    doc = await COL.find_one({"_id": ObjectId(job_id)})
    if not doc:
        raise HTTPException(404, "Job not found")
    out = {**doc, "id": str(doc["_id"])}
    out.pop("_id", None)

    if out.get("status") == "done" and out.get("artifact_key"):
        out["downloadUrl"] = presign_get_artifact(out["artifact_key"])
    return out