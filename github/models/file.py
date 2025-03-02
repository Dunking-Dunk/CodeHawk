from pydantic import BaseModel
from typing import Optional, List

class ProjectFile(BaseModel):
    file_content: str