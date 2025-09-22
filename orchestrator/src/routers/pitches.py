from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone
from bson import ObjectId
from ..db.mongo import db
from ..models.schemas import PitchIn, PitchDB, PitchOut
from ..services.obs_sign import presign_get_pitch_artifact, pitch_artifact_exists


router = APIRouter(prefix="/api", tags=["pitches"])
COL = db["pitches"]


@router.post("/pitches")
async def create_pitch(payload: PitchIn):
    """Create a new pitch job from an uploaded video"""
    # Verify that the upload exists
    uploads_col = db["uploads"]
    upload_doc = await uploads_col.find_one({"_id": ObjectId(payload.uploadId)})
    if not upload_doc:
        raise HTTPException(404, "Upload not found")
    
    # Create the pitch job
    pitch = PitchDB(
        uploadId=payload.uploadId,
        status="queued"
    )
    
    await COL.insert_one(pitch.model_dump(by_alias=True))
    
    return {
        "pitchId": str(pitch.id),
        "status": "queued"
    }


@router.get("/pitches/{pitch_id}")
async def get_pitch(pitch_id: str):
    """Get pitch status and download URLs"""
    try:
        oid = ObjectId(pitch_id)
    except Exception:
        raise HTTPException(400, "Invalid pitch ID format")
    
    doc = await COL.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Pitch not found")
    
    # Convert to response format
    response = {
        "id": str(doc["_id"]),
        "uploadId": doc["uploadId"],
        "status": doc["status"],
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"],
        "error_msg": doc.get("error_msg")
    }
    
    # Add signed URLs for artifacts if completed
    if doc["status"] == "completed":
        # Generate signed URLs for each artifact if they exist
        if doc.get("deck_key"):
            response["deckUrl"] = presign_get_pitch_artifact(doc["deck_key"])
        
        if doc.get("script_key"):
            response["scriptUrl"] = presign_get_pitch_artifact(doc["script_key"])
        
        if doc.get("preview_key"):
            response["previewUrl"] = presign_get_pitch_artifact(doc["preview_key"])
    
    return response


@router.patch("/pitches/{pitch_id}/status")
async def update_pitch_status(
    pitch_id: str,
    status: str,
    error_msg: str = None,
    deck_key: str = None,
    script_key: str = None,
    preview_key: str = None
):
    """Update pitch status (internal endpoint for worker)"""
    try:
        oid = ObjectId(pitch_id)
    except Exception:
        raise HTTPException(400, "Invalid pitch ID format")
    
    # Validate status
    valid_statuses = ["queued", "processing", "completed", "failed"]
    if status not in valid_statuses:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid_statuses}")
    
    update_data = {
        "status": status,
        "updated_at": datetime.now(timezone.utc)
    }
    
    if error_msg:
        update_data["error_msg"] = error_msg
    
    if deck_key:
        update_data["deck_key"] = deck_key
    
    if script_key:
        update_data["script_key"] = script_key
    
    if preview_key:
        update_data["preview_key"] = preview_key
    
    result = await COL.update_one(
        {"_id": oid},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(404, "Pitch not found")
    
    return {"ok": True, "updated": result.modified_count > 0}
