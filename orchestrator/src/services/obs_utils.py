import os
from dotenv import load_dotenv; load_dotenv()

OBS_ENDPOINT = os.getenv("OBS_ENDPOINT")
OBS_AK = os.getenv("OBS_AK")
OBS_SK = os.getenv("OBS_SK")
DEFAULT_GET_EXPIRES = int(os.getenv("OBS_GET_EXPIRES", "86400"))  # 24h

try:
    from obs import ObsClient
    _obs = ObsClient(access_key_id=OBS_AK, secret_access_key=OBS_SK, server=OBS_ENDPOINT)
except Exception:
    _obs = None

def obs_signed_get(bucket: str, key: str, expires: int | None = None) -> str:
    if not _obs:
        raise RuntimeError("OBS client no inicializado (revisa AK/SK/ENDPOINT).")
    exp = int(expires) if expires is not None else DEFAULT_GET_EXPIRES
    resp = _obs.createSignedUrl('GET', bucket, key, expires=exp)
    # el SDK devuelve un objeto con .signedUrl
    url = getattr(resp, "signedUrl", None) or (resp.get("signedUrl") if isinstance(resp, dict) else None)
    if not url:
        raise RuntimeError("OBS createSignedUrl no devolvió signedUrl.")
    return url
