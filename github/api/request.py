import asyncio
from typing import Optional, Type, TypeVar, Any, Dict, List
from pathlib import Path
from dataclasses import dataclass
import aiohttp
from pydantic import ValidationError
import time
import os
from dotenv import load_dotenv
from multipledispatch import dispatch

#custom imports
from github.api.utils.timeout import async_timeout
from github.api.models import *
from github.core.exception import (_handle_http_error, GithubException, RateLimitExceededException)
from .utils.endpoints import *

load_dotenv()
TIMEOUT: int = 45
T = TypeVar('T')


@dataclass
class APIConfig:
    """COnfiguration for the Github API Operations. It contains params such as 
    Attributes:
    user: str
        The username of the user in Github
    repo: str
        The Repository  to clone from Github
    branch: str, optional
        The Repository Branch to get files from. Initialized to None
    token: str, optional
        The Github API Key of the user inorder to query the GITHUB API 
    params: dict, optional
        Other arguments
    """
    user: str
    repo: str
    branch: Optional[str] = None
    token: Optional[str] = None
    path: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    
    
    
class RateLimitState:
    """Async Rate Limit and access identifier function to track number of requests made to the Github API
    Attributes: 
    remaining: int, optional
        Keeps tracks of remaining number of requests for a paticular Github Session
    limit: int, optional
        The total number of requests which can be made in a single day
    reset: int, optional
        The reset limit of the Github API
    last_updated: float
        Keeps track of the last made request and the time
    """
    def __init__(self):
        self.remaining: Optional[int] = None
        self.limit: Optional[int] = None
        self.reset: Optional[int] = None
        self.last_updated: float = 0.0

    def update_rate_state(self, headers: dict):
        """Updates the state of the Attributes defined in the function for easier configurations

        Args:
        headers: dict
            The request header to api.github.com    

        """
        self.remaining = int(headers.get('X-RateLimit-Remaining', 0))
        self.limit = int(headers.get('X-RateLimit-Limit', 0))
        self.reset = int(headers.get('X-RateLimit-Reset', 0))
        self.last_updated = time.time()

    @property
    def should_throttle(self) -> bool:
        if self.remaining is None or self.reset is None:
            return False
        return self.remaining <= 0 and time.time() < self.reset
    
class APIHandler:
    """API Handler class for the regulating the Github Requests and other required details
    Attributes:
    config: APIConfig
        The configuration class for the API Handler
    """
    def __init__(self, config: APIConfig):
        self.config = config
        self.git_token = config.token
        self.rate_limit = RateLimitState()
        self.throttle = self.rate_limit.should_throttle
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Github-Client'
        }
        
        if self.git_token:
            self.headers["Authorization"] = f"token {self.git_token}"
        self.session = aiohttp.ClientSession(headers=self.headers)
        
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.session.close()
        
    def get_config(self, required: List[str]) -> Dict[str, Any]:
        """Validate and return required configuration parameters"""
        config_map = {
            'user': self.config.user,
            'repo': self.config.repo,
            'branch': self.config.branch,
            'path': self.config.path,
            'token': self.config.token,
            'params': self.config.params
        }
        
        missing = [field for field in required if not config_map.get(field)]
        if missing:
            raise ValueError(f"Missing required config fields: {missing}")
        
        return {k: v for k, v in config_map.items() if k in required}
        
        
    async def _check_rate_limit(self):
        if self.throttle:
            wait_time = max(0, self.rate_limit.reset - time.time())
            await asyncio.sleep(wait_time)
            
    @async_timeout(TIMEOUT)
    async def _make_request(self, url: str, model: Type[T]) -> T:
        """Function to make the curl command request for the url given. 

        Args:
            url (str): The url to make the request to
            model (Type[T]): Structure of the Github Request/Response which it should follow
        Raises:
            GithubException: Network Error 
            GithubException: Validation Error of the Pydantic class during request/response

        Returns:
            T: The Pydantic Dataclass Model specified in the parameters
        """
        await self._check_rate_limit()

        try:
            async with self.session.get(url, params=self.config.params) as response:
                if response.status != 200:
                    # print(response)
                    await _handle_http_error(Exception, response)
                
                self.rate_limit.update_rate_state(response.headers)
                data = await response.json()
                return model(**data)
        except aiohttp.ClientError as e:
            raise GithubException(f"Network error: {str(e)}") from e
        except ValidationError as e:
            raise GithubException(f"Validation error: {str(e)}") from e
        
    async def get_rate_limit(self) -> RateLimitResponse:
        return await self._make_request(RATE_LIMIT_URL, RateLimitResponse)

    async def get_user(self) -> GitHubUser:
        """
        Retrieve GitHub user profile information.

        This method fetches user details such as username, profile URL, avatar, 
        name, public repository count, followers, and following.

        Returns:
            GitHubUser: A model containing user profile details.

        Raises:
            aiohttp.ClientError: If an HTTP request fails.
        """
        config = self.get_config(['user'])
        url = USER_URL.format(user=config['user'])
        return await self._make_request(url, GitHubUser)

    async def get_repo(self) -> Repository:
        """
        Retrieve repository details.

        This method fetches details of a GitHub repository, including metadata 
        such as name, description, owner, visibility, and more.

        Returns:
            Repository: A model containing repository details.

        Raises:
            aiohttp.ClientError: If an HTTP request fails.
        """
        config = self.get_config(['user', 'repo'])
        url = REPO_URL.format(user=config['user'], repo=config['repo'])
        return await self._make_request(url, Repository)

    async def get_repo_tree(self) -> RepoTreeModel:
        """
        Retrieve the repository tree structure.

        This method fetches the repository's file structure for a specific 
        branch, providing a hierarchical view of the repository's contents.

        Returns:
            RepoTreeModel: A model representing the repository's tree structure.

        Raises:
            aiohttp.ClientError: If an HTTP request fails.
        """
        config = self.get_config(['user', 'repo', 'branch'])
        url = TREE_URL.format(
            user=config['user'],
            repo=config['repo'],
            branch=config['branch']
        )
        return await self._make_request(url, RepoTreeModel)
    

    async def get_raw_file(self, path: Optional[str] = None) -> ProjectFile:
        """
        Retrieve raw file content from repository.
        
        Args:
            path (str, optional): Specific file path to fetch. Uses config.path if not provided
            
        Returns:
            ProjectFile: Contains file content and metadata
        """
        final_path = path or self.config.path
        if not final_path:
            raise ValueError("No path specified for raw file retrieval")

        config = self.get_config(['user', 'repo', 'branch'])
        url = RAW_FILE_BY_BRANCH.format(
            user=config['user'],
            repo=config['repo'],
            branch=config['branch'],
            path=final_path
        )
        
        try:
            async with self.session.get(url) as response:
                response.raise_for_status()
                content = await response.text()
                return ProjectFile(file_content=content)
        except aiohttp.ClientError as e:
            await _handle_http_error(response)
            
@async_timeout(TIMEOUT)
async def check_api_available() -> bool:
    """
    Check the availability of the GitHub API.

    This function uses a subprocess call to `curl` to send a request to the GitHub API 
    and determine if it is accessible. A successful API response should return HTTP `200 OK`.

    Returns:
        bool: True if the GitHub API is reachable and returns `200 OK`, otherwise False.

    Raises:
        OSError: If an error occurs while creating the subprocess.
        asyncio.SubprocessError: If an error occurs while executing the subprocess.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-I", "https://api.github.com",
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return proc.returncode == 0
    except (OSError):
        return False

async def github_api_handler(config: APIConfig) -> Dict[str, Any]:
    """
    Handle GitHub API operations asynchronously.

    This function orchestrates multiple API requests based on the provided configuration.
    It first checks API availability, then fetches various GitHub resources such as user details, 
    repository details, repository tree structure, and raw file contents if applicable.
    
    If the API rate limit is exceeded, it waits for the reset time and retries the request.

    Args:
        config (APIConfig): The API configuration containing user, repository, branch, and file path details.

    Returns:
        Dict[str, Any]: A dictionary containing the requested GitHub data with the following possible keys:
            - `rate_limit`: Rate limit information.
            - `user`: GitHub user details.
            - `repo`: Repository metadata.
            - `tree` (optional): Repository file tree (if a branch is specified).
            - `file` (optional): Raw file content (if both path and branch are specified).

    Raises:
        GithubException: If the GitHub API is unavailable.
        RateLimitExceededException: If the API rate limit is exceeded, waits until reset before retrying.
    """
    if not await check_api_available():
        raise GithubException("GitHub API unavailable")

    async with APIHandler(config) as handler:
        results = {}
        
        try:
            # Get basic information
            results.update({
                "rate_limit": await handler.get_rate_limit(),
                "user": await handler.get_user(),
                "repo": await handler.get_repo()
            })

            # Handle file content retrieval
            results["files"] = {}
            
            if config.path:
                results["files"][config.path] = (await handler.get_raw_file()).file_content
            elif config.branch:
                results["tree"] = await handler.get_repo_tree()
                blob_paths = results["tree"].blobs
                print(blob_paths)
                
                for file_path in blob_paths:
                    results["files"][file_path] = (await handler.get_raw_file(file_path)).file_content

            return results
        
        except RateLimitExceededException as e:
            reset_time = handler.rate_limit.reset
            wait_time = max(0, reset_time - time.time())
            await asyncio.sleep(wait_time)
            return await github_api_handler(config)