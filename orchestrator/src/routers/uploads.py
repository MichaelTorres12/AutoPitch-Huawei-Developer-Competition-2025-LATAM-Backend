from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from bson import ObjectId
from ..db.mongo import db
from ..services.obs_sign import upload_bytes_to_uploads, presign_get_upload
from datetime import datetime, timezone
import os


router = APIRouter(prefix="/api", tags=["uploads"])
COL = db["uploads"]


@router.post("/uploads")
async def upload_video(
    file: UploadFile = File(...),
    path: str | None = Form(None),
):
    try:
        data = await file.read()
        size_bytes = len(data)
        if size_bytes == 0:
            raise HTTPException(400, "Empty file")

        oid = ObjectId()
        _, ext = os.path.splitext(file.filename or "")
        safe_ext = ext if ext.lower() in {".mp4", ".mov", ".mkv", ".webm", ".avi"} else ".mp4"

        rel_dir = (path or "videos").strip().strip("/")
        key = f"{rel_dir}/{str(oid)}{safe_ext}"

        content_type = file.content_type or "application/octet-stream"
        upload_bytes_to_uploads(key, data, content_type)

        doc = {
            "_id": oid,
            "key": key,
            "original_filename": file.filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        await COL.insert_one(doc)

        return {
            "id": str(oid),
            "key": key,
            "size": size_bytes,
            "contentType": content_type,
            "getUrl": presign_get_upload(key),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Upload failed: {e}")


@router.get("/uploads/{upload_id}")
async def get_upload(upload_id: str):
    try:
        oid = ObjectId(upload_id)
    except Exception:
        raise HTTPException(400, "Invalid id")

    doc = await COL.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Not found")

    key = doc.get("key")
    url = presign_get_upload(key) if key else None

    return {
        "id": str(doc["_id"]),
        "key": key,
        "original_filename": doc.get("original_filename"),
        "content_type": doc.get("content_type"),
        "size_bytes": doc.get("size_bytes"),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "getUrl": url,
    }


