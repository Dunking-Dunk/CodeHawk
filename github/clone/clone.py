import asyncio
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple
from pathlib import Path

from .utils.timeout import async_timeout
TIMEOUT: int = 45


@dataclass
class CloneConfig:
    """Configuration for cloning GitHub Repo
    Holds params for cloning repo to a local path including the
    repository's URL, the target local path and optional params  
    
    Attributes:
    url: str
        The GitHub repo's URL to clone
    local_path: str
        The local directory where the repo should be cloned
    branch: str, optional
        The branch to clone (default is None)
    subpath: str
        The subpath to clone from the repo(default is "/")
    """
    
    url: str
    local_path: str
    subpath: str = "/"
    branch: Optional[str] = None
    blob: bool = False
    
@async_timeout(TIMEOUT)
async def clone_repo(config: CloneConfig) -> None:
    """Clones a repo to local_path based on the provided configurations
    Handles: Cloning repo to local file system, and can clone specific 
    branch if provided, also raises exception

    Args:
        config (CloneConfig): Configuration settings for cloning the Repo
        
    Raises:
        ValueError: if repo url is not valid or not found
        OSError: if repo couldnt be cloned to the specified directory
    """
    url: str = config.url
    local_path: str = config.local_path
    branch: Optional[str] = config.branch
    partial_clone: bool = config.subpath != "/"

    # Create parent directory if it doesn't exist
    parent_dir = Path(local_path).parent
    try:
        os.makedirs(parent_dir, exist_ok=True)
    except OSError as exc:
        raise OSError(f"Failed to create parent directory {parent_dir}: {exc}") from exc

    if not await _check_repo_exists(url):
        raise ValueError("Repository not found, make sure it is public")

    # Build the Git clone command
    clone_cmd = ["git", "clone", "--single-branch", "--depth=1"]
    if partial_clone:
        clone_cmd += ["--filter=blob:none", "--sparse"]
    if branch and branch.lower() not in ("main", "master"):
        clone_cmd += ["--branch", branch]

    clone_cmd += [url, local_path]

    await _run_command(*clone_cmd)
    if partial_clone:
        checkout_cmd = ["git", "-C", local_path, "sparse-checkout", "set"]

        # Add subpath for sparse checkout
        if config.blob:
            checkout_cmd += [config.subpath.lstrip("/")[:-1]]
        else:
            checkout_cmd += [config.subpath.lstrip("/")]

        await _run_command(*checkout_cmd)
        
        
def _get_status_code(response: str) -> int:
    """Gets the status code from an HTTP response

    Args:
        response (str): The HTTP Response String

    Returns:
        int: Status code of the response
    """
    status_line = response.splitlines()[0].strip()
    status_code = int(status_line.split(" ", 2)[1])
    return status_code

async def check_git_installed() -> None:
    """Checking if Git is installed and accessible on the system.

    Raises:
        RuntimeError: If Git is not installed or if the Git command exist with a non-zero status
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "git",
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            error_message = stderr.decode().strip() if stderr else "Git not found"
            raise RuntimeError(f"Git is not installed or accessible")
    except FileNotFoundError as e:
        raise RuntimeError("Git is not installed, Please install GIT before proceeding.")
    
    
async def _run_command(*args: str) -> Tuple[bytes, bytes]:
    """Executes the command and captures output

    Parameters: 
        *ars[str]: The command to execute
        
    Raises:
        RuntimeError: If non-zero status is returned

    Returns:
        Tuple[bytes, bytes]: Contains [stdout: stderr] of the command output
    """
    await check_git_installed()

    # Execute the requested command
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        error_message = stderr.decode().strip()
        raise RuntimeError(f"Command failed: {' '.join(args)}\nError: {error_message}")

    return stdout, stderr

async def fetch_remote_branch_list(url: str) -> List[str]:
    """Feteches the branch list from remote git repo

    Args:
        url (str): The url of the Git Repo

    Returns:
        List[str]: List of branches for the repo
    """
    fetch_branches_command = ["git", "ls-remote", "--heads", url]
    stdout, _ = await _run_command(*fetch_branches_command)
    stdout_decoded = stdout.decode()

    return [
        line.split("refs/heads/", 1)[1]
        for line in stdout_decoded.splitlines()
        if line.strip() and "refs/heads/" in line
    ]

async def _check_repo_exists(url: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "curl",
        "-I",
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    if proc.returncode != 0:
        return False

    response = stdout.decode()
    status_code = _get_status_code(response)

    if status_code in (200, 301):
        return True

    if status_code in (404, 302):
        return False

    raise RuntimeError(f"Unexpected status code: {status_code}")