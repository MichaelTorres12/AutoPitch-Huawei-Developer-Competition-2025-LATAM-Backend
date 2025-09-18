import os
from urllib.parse import quote_plus
from dotenv import load_dotenv; load_dotenv()


class Settings:
    # Raw URI (if already valid). If user/password contain special chars, prefer the component vars below.
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/autopitch")

    # Component-based configuration (preferred for Huawei Cloud DDS)
    MONGO_SCHEME: str = os.getenv("MONGO_SCHEME", "mongodb")  # "mongodb" or "mongodb+srv"
    MONGO_USERNAME: str | None = os.getenv("MONGO_USERNAME")
    MONGO_PASSWORD: str | None = os.getenv("MONGO_PASSWORD")
    MONGO_HOSTS: str = os.getenv("MONGO_HOSTS", "localhost:27017")  # comma-separated host:port list
    MONGO_DB: str = os.getenv("MONGO_DB", "autopitch")
    MONGO_AUTH_SOURCE: str | None = os.getenv("MONGO_AUTH_SOURCE", "admin")
    MONGO_REPLICA_SET: str | None = os.getenv("MONGO_REPLICA_SET")
    MONGO_TLS: bool = os.getenv("MONGO_TLS", "false").lower() in ("1", "true", "yes")
    MONGO_OPTIONS: str | None = os.getenv("MONGO_OPTIONS")  # e.g. "readPreference=secondaryPreferred&retryWrites=true"
    MONGO_TLS_CA_FILE: str | None = os.getenv("MONGO_TLS_CA_FILE")  # optional path to CA bundle if required

    CORS_ORIGIN: str = os.getenv("CORS_ORIGIN", "*")
    # OBS
    OBS_AK = os.getenv("OBS_AK")
    OBS_SK = os.getenv("OBS_SK")
    # Accept both OBS_REGION and legacy HWC_REGION
    OBS_REGION = os.getenv("OBS_REGION") or os.getenv("HWC_REGION", "ap-southeast-3")
    OBS_ENDPOINT = os.getenv("OBS_ENDPOINT", f"obs.{OBS_REGION}.myhuaweicloud.com")
    BUCKET_UPLOADS = os.getenv("OBS_BUCKET_UPLOADS", "autopitch-uploads")
    BUCKET_ARTIFACTS = os.getenv("OBS_BUCKET_ARTIFACTS", "autopitch-artifacts")
    # Signature expirations
    OBS_PUT_EXPIRES: int = int(os.getenv("OBS_PUT_EXPIRES", "900"))
    OBS_GET_EXPIRES: int = int(os.getenv("OBS_GET_EXPIRES", "86400"))

    # firma (segundos)
    OBS_PUT_EXPIRES = int(os.getenv("OBS_PUT_EXPIRES", "900"))       # 15 min
    OBS_GET_EXPIRES = int(os.getenv("OBS_GET_EXPIRES", "86400"))     # 24 h

    def _build_mongo_uri(self) -> str:
        """Build a safe RFC 3986-compliant MongoDB URI using component vars when available.

        This avoids InvalidURI errors when usernames/passwords contain special characters.
        """
        if self.MONGO_USERNAME and self.MONGO_PASSWORD:
            user = quote_plus(self.MONGO_USERNAME)
            password = quote_plus(self.MONGO_PASSWORD)
            hosts = self.MONGO_HOSTS
            db_name = self.MONGO_DB or "admin"

            params: list[str] = []
            if self.MONGO_AUTH_SOURCE:
                params.append(f"authSource={quote_plus(self.MONGO_AUTH_SOURCE)}")
            if self.MONGO_REPLICA_SET:
                params.append(f"replicaSet={quote_plus(self.MONGO_REPLICA_SET)}")
            if self.MONGO_TLS:
                # pymongo prefers tls=true over ssl=true
                params.append("tls=true")
            if self.MONGO_OPTIONS:
                params.append(self.MONGO_OPTIONS.strip("?&"))

            query = ("?" + "&".join([p for p in params if p])) if params else ""
            scheme = "mongodb+srv" if self.MONGO_SCHEME.lower() == "mongodb+srv" else "mongodb"
            return f"{scheme}://{user}:{password}@{hosts}/{db_name}{query}"

        # Fallback to the provided URI (assumed to already be valid/escaped)
        return self.MONGO_URI


settings = Settings()
# Build a safe URI if component credentials are provided
settings.MONGO_URI = settings._build_mongo_uri()
