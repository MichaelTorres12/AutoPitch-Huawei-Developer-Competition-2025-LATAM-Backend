from obs import ObsClient
from ..core.config import settings

def _client():
    # server debe ser sin https://
    server = settings.OBS_ENDPOINT.replace("https://", "").replace("http://", "")
    return ObsClient(
        access_key_id=settings.OBS_AK,
        secret_access_key=settings.OBS_SK,
        server=server,
        is_secure=True
    )

def presign_put(key: str) -> str:
    cli = _client()
    resp = cli.createSignedUrl(
        'PUT',
        settings.OBS_BUCKET_UPLOADS,
        key,
        expires=settings.OBS_PUT_EXPIRES
    )
    return resp['signedUrl']

def presign_get_artifact(key: str) -> str:
    cli = _client()
    resp = cli.createSignedUrl(
        'GET',
        settings.OBS_BUCKET_ARTIFACTS,
        key,
        expires=settings.OBS_GET_EXPIRES
    )
    return resp['signedUrl']

def object_exists_in_uploads(key: str) -> bool:
    cli = _client()
    r = cli.getObjectMetadata(settings.OBS_BUCKET_UPLOADS, key)
    return r.status < 300