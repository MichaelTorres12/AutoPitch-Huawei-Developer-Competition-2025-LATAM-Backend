from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict

JobTone = Literal["executive","technical","inspiring"]
JobGoal = Literal["investors","hackathon","sales"]
JobStatus = Literal["queued","uploaded","processing","ready","failed"]

class JobCreateRequest(BaseModel):
    goal: JobGoal
    tone: JobTone = "executive"
    slides: int = 10
    filename: str
    filesize: int

class JobOut(BaseModel):
    id: str
    status: JobStatus
    upload_url: Optional[str] = None
    obs_key: Optional[str] = None
    artifacts: Optional[Dict[str, str] | Dict[str, List[str]]] = None
