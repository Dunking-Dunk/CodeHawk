from pydantic import BaseModel
from typing import Optional

class GitHubUser(BaseModel):
    login: str
    html_url: str
    avatar_url: str
    name: Optional[str] = None
    public_repos: Optional[int] = None
    followers: Optional[int] = None
    following: Optional[int] = None