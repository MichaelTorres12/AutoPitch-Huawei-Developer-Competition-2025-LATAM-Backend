from datetime import datetime, timezone
from bson import ObjectId
from ..db.mongo import jobs

async def process_job(job_id: ObjectId, obs_key: str):
    # MVP: simula procesamiento y escribe artifacts "falsos"
    await jobs.update_one({"_id": job_id}, {"$set": {"status": "processing", "updatedAt": datetime.now(timezone.utc)}})

    # Simulación mínima: “genera” rutas de salida en artifacts (no sube nada real)
    artifacts = {
        "pptx": f"artifacts/{job_id}/deck.pptx",
        "script": f"artifacts/{job_id}/script.md",
        "frames": [f"artifacts/{job_id}/frames/f1.png", f"artifacts/{job_id}/frames/f2.png"],
    }

    await jobs.update_one(
        {"_id": job_id},
        {"$set": {"status": "ready", "artifacts": artifacts, "updatedAt": datetime.now(timezone.utc)}}
    )
