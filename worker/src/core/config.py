import os
from urllib.parse import quote_plus
from dotenv import load_dotenv; load_dotenv()


class Settings:
    # Raw URI fallback
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/autopitch")

    # Component-based configuration
    MONGO_SCHEME: str = os.getenv("MONGO_SCHEME", "mongodb")  # "mongodb" or "mongodb+srv"
    MONGO_USERNAME: str | None = os.getenv("MONGO_USERNAME")
    MONGO_PASSWORD: str | None = os.getenv("MONGO_PASSWORD")
    MONGO_HOSTS: str = os.getenv("MONGO_HOSTS", "localhost:27017")
    MONGO_DB: str = os.getenv("MONGO_DB", "autopitch")
    MONGO_AUTH_SOURCE: str | None = os.getenv("MONGO_AUTH_SOURCE", "admin")
    MONGO_REPLICA_SET: str | None = os.getenv("MONGO_REPLICA_SET")
    MONGO_TLS: bool = os.getenv("MONGO_TLS", "false").lower() in ("1", "true", "yes")
    MONGO_OPTIONS: str | None = os.getenv("MONGO_OPTIONS")
    MONGO_TLS_CA_FILE: str | None = os.getenv("MONGO_TLS_CA_FILE")

    HWC_REGION = os.getenv("HWC_REGION", "ap-southeast-3")
    OBS_ENDPOINT = os.getenv("OBS_ENDPOINT", f"obs.{HWC_REGION}.myhuaweicloud.com")
    ORCH_URL = os.getenv("ORCHESTRATOR_INTERNAL_URL", "http://orchestrator:8080")

    def _build_mongo_uri(self) -> str:
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
                params.append("tls=true")
            if self.MONGO_OPTIONS:
                params.append(self.MONGO_OPTIONS.strip("?&"))

            query = ("?" + "&".join([p for p in params if p])) if params else ""
            scheme = "mongodb+srv" if self.MONGO_SCHEME.lower() == "mongodb+srv" else "mongodb"
            return f"{scheme}://{user}:{password}@{hosts}/{db_name}{query}"
        return self.MONGO_URI


settings = Settings()
settings.MONGO_URI = settings._build_mongo_uri()
