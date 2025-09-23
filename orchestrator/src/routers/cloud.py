# src/routers/cloud.py (reemplaza esa parte)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from bson import ObjectId
import anyio

from ..db.mongo import mongo_client
from ..services.cloud_pipeline import process_upload_doc

router = APIRouter()

class ProcessIn(BaseModel):
    uploadId: str
    top_k: int = 8
    frame_where: str = "mid"   # start | mid | end
    frame_limit: int = 12
    make_srt: bool = True
    language: str = "es"
    # Pitch deck customization
    objective: str | None = None
    tone: str | None = None
    slidesNumber: str | None = None  # admite rango "6-8" o número "7"

@router.post("/process-from-upload")
async def process_from_upload(body: ProcessIn):
    db = mongo_client.get_default_database()
    try:
        up = await db["uploads"].find_one({"_id": ObjectId(body.uploadId)})
    except Exception:
        up = await db["uploads"].find_one({"_id": body.uploadId})
    if not up:
        raise HTTPException(404, "uploadId no encontrado")

    # ✅ Ejecuta el pipeline en hilo con kwargs dentro del lambda
    result = await anyio.to_thread.run_sync(
        lambda: process_upload_doc(
            up,
            top_k=body.top_k,
            frame_where=body.frame_where,
            frame_limit=body.frame_limit,
            make_srt=body.make_srt,
            language=body.language,
            objective=body.objective,
            tone=body.tone,
            slides_number=body.slidesNumber,
        )
    )

    await db["pitches"].insert_one({
        "uploadId": body.uploadId,
        "status": "done",
        "created_at": result["created_at"],
        "updated_at": result["updated_at"],
        "error_msg": None,
        "audio_key": result["audio"].replace("obs://", "").split("/", 1)[-1]
                     if str(result["audio"]).startswith("obs://") else result["audio"],
        "frames_prefix": result["frames_prefix"],
        "frames": result["frames"],
        "transcript": result["transcript"],
        "highlights": result["highlights"],
        "srt_key": result["srt_key"],
        "pitch_deck": result.get("pitch_deck"),
    })

    return {
        "ok": True,
        "input_video": result["input_video"],
        "audio": result["audio"],
        "frames": result["frames"],
        "srt_key": result["srt_key"],
        "highlights": result["highlights"],
        "transcript_sentences": len(result["transcript"]["sentences"]),
        "pitch_deck": result.get("pitch_deck"),
        # Signed URLs (like in /api/uploads behavior)
        "input_video_url": result.get("input_video_url"),
        "audio_url": result.get("audio_url"),
        "frame_urls": result.get("frame_urls"),
        "srt_url": result.get("srt_url"),
    }
