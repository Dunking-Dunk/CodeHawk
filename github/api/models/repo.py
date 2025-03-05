from pydantic import BaseModel
from typing import Optional, Dict, List

#custom model
from .owner import GitHubUser

class Repository(BaseModel):
    name: str
    full_name: str
    description: Optional[str]
    html_url: str
    default_branch: str
    language: Optional[str]
    stargazers_count: int
    forks_count: int
    open_issues_count: int
    owner: GitHubUser