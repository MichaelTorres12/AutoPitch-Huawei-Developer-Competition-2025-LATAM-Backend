from pydantic import BaseModel, Field, field_validator
from typing import Literal, Optional
from bson import ObjectId
from datetime import datetime, timezone


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return v
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


JobTone = Literal["technical","executive","inspiring"]
JobGoal = Literal["investors","hackathon","sales"]
JobStatus = Literal["created","uploading","uploaded","processing","done","error"]

# Pitch schemas
PitchStatus = Literal["queued","processing","completed","failed"]


class JobIn(BaseModel):
    goal: JobGoal
    tone: JobTone = "executive"
    slides: int = 8

    @field_validator("slides")
    @classmethod
    def validate_slides(cls, v: int) -> int:
        if not (1 <= v <= 20):
            raise ValueError("slides must be between 1 and 20")
        return v


class JobDB(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    status: JobStatus = "created"
    goal: JobGoal
    tone: JobTone
    slides: int
    obs_key: Optional[str] = None
    artifact_key: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_msg: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


class JobOut(BaseModel):
    id: str
    status: JobStatus
    goal: JobGoal
    tone: JobTone
    slides: int
    obs_key: Optional[str] = None
    artifact_key: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    error_msg: Optional[str] = None
    downloadUrl: Optional[str] = None


class PitchIn(BaseModel):
    uploadId: str

    @field_validator("uploadId")
    @classmethod
    def validate_upload_id(cls, v: str) -> str:
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid uploadId format")
        return v


class PitchDB(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    uploadId: str
    status: PitchStatus = "queued"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_msg: Optional[str] = None
    # Artifacts keys
    deck_key: Optional[str] = None
    script_key: Optional[str] = None
    preview_key: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


class PitchOut(BaseModel):
    id: str
    uploadId: str
    status: PitchStatus
    created_at: datetime
    updated_at: datetime
    error_msg: Optional[str] = None
    # URLs firmadas para descarga
    deckUrl: Optional[str] = None
    scriptUrl: Optional[str] = None
    previewUrl: Optional[str] = None
