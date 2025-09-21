from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConfigurationError
from ..core.config import settings


client_kwargs: dict = {}
# Ensure TLS is enabled if explicitly requested or when a CA file is provided
if settings.MONGO_TLS or settings.MONGO_TLS_CA_FILE:
    client_kwargs["tls"] = True
if settings.MONGO_TLS_CA_FILE:
    # Prefer passing the CA file via kwargs to avoid escaping issues in URIs on Windows
    client_kwargs["tlsCAFile"] = settings.MONGO_TLS_CA_FILE

mongo_client = AsyncIOMotorClient(settings.MONGO_URI, **client_kwargs)

# Evita evaluar truthiness sobre Database (lanza NotImplementedError)
try:
    db = mongo_client.get_default_database()
except ConfigurationError:
    db = None

if db is None:
    db = mongo_client[settings.MONGO_DB or "autopitch"]

jobs = db["jobs"]
