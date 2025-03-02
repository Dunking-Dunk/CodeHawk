from git import Repo
import os
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

def get_repo_name(url: str) -> str:
    """Extract repository name from GitHub URL"""
    path = urlparse(url).path
    repo_name = path.split("/")[-1]
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]
    return repo_name

def create_dir_name(base_path: str, repo_name: str) -> Path:
    """Create unique directory for cloning"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    uid = uuid.uuid4().hex[:6]
    dir_name = f"{repo_name}_{timestamp}_{uid}"
    
    full_path = Path(base_path) / dir_name
    full_path.mkdir(parents=True, exist_ok=True)
    return full_path

def clone_repo(url: str, base_clone_path: str) -> Optional[Path]:
    """Clone repository into unique subdirectory"""
    
    try:
        repo_name = get_repo_name(url)
        clone_path = create_dir_name(base_clone_path, repo_name)
        print(f"Cloning {url} into {clone_path}")
        Repo.clone_from(url, str(clone_path))
        return clone_path
    except Exception as e:
        print(f"Error cloning repository: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    BASE_CLONE_DIR = os.getenv('CLONE_DIR')
    repo_url = "https://github.com/octocat/Hello-World.git"
    
    Path(BASE_CLONE_DIR).mkdir(exist_ok=True)
    cloned_path = clone_repo(repo_url, BASE_CLONE_DIR)
    if cloned_path:
        print(f"Successfully cloned to: {cloned_path}")