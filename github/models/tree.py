from pydantic import BaseModel
from typing import Optional, List

class TreeItemModel(BaseModel):
    path: str
    mode: str
    type: str  # "blob" for files, "tree" for directories
    sha: str
    size: Optional[int] = None  # Only present for files
    url: str

class RepoTreeModel(BaseModel):
    sha: str
    url: str
    tree: List[TreeItemModel]
    
    @property
    def blobs(self) -> List[TreeItemModel]:
        return [item.path for item in self.tree if item.type == "blob"]