from fastapi import APIRouter, Query
from ..services.obs_utils import obs_signed_get

router = APIRouter(prefix="/cloud", tags=["cloud"])

@router.get("/signed-get")
async def signed_get(
    bucket: str = Query(..., description="Nombre del bucket"),
    key: str = Query(..., description="Clave/objeto dentro del bucket, p.ej. audio/ID.mp3"),
    expires: int | None = Query(None, description="Segundos de validez; si no se manda se usa OBS_GET_EXPIRES")
):
    url = obs_signed_get(bucket, key, expires)
    return {"bucket": bucket, "key": key, "expires": expires, "url": url}
