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
        settings.BUCKET_UPLOADS,
        key,
        expires=settings.OBS_PUT_EXPIRES
    )
    return resp['signedUrl']

def presign_get_artifact(key: str) -> str:
    cli = _client()
    resp = cli.createSignedUrl(
        'GET',
        settings.BUCKET_ARTIFACTS,
        key,
        expires=settings.OBS_GET_EXPIRES
    )
    return resp['signedUrl']

def object_exists_in_uploads(key: str) -> bool:
    cli = _client()
    r = cli.getObjectMetadata(settings.BUCKET_UPLOADS, key)
    return r.status < 300


def upload_bytes_to_uploads(key: str, data: bytes, content_type: str | None = None) -> None:
    cli = _client()
    # Set HTTP header via 'headers' param; 'contentType' kwarg is not supported
    headers = {"Content-Type": content_type} if content_type else None
    resp = cli.putContent(settings.BUCKET_UPLOADS, key, data, headers=headers)
    if not (200 <= resp.status < 300):
        # Minimal error surface; caller handles exceptions
        raise RuntimeError(f"OBS putContent failed: {resp.status}")


def presign_get_upload(key: str) -> str:
    cli = _client()
    resp = cli.createSignedUrl(
        'GET',
        settings.BUCKET_UPLOADS,
        key,
        expires=settings.OBS_GET_EXPIRES
    )
    return resp['signedUrl']


def presign_get_pitch_artifact(key: str) -> str:
    """Generate presigned URL for pitch artifacts (deck, script, preview)"""
    cli = _client()
    resp = cli.createSignedUrl(
        'GET',
        settings.BUCKET_ARTIFACTS,
        key,
        expires=settings.OBS_GET_EXPIRES
    )
    return resp['signedUrl']


def pitch_artifact_exists(key: str) -> bool:
    """Check if a pitch artifact exists in OBS"""
    cli = _client()
    r = cli.getObjectMetadata(settings.BUCKET_ARTIFACTS, key)
    return r.status < 300