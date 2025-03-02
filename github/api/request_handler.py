import requests
from requests.exceptions import HTTPError, RequestException
from pydantic import ValidationError
from typing import Optional, Type, TypeVar, Any, Dict
import time

# Custom modules
from github.core.exception import (
    RateLimitExceededException, BadCredentialsException, NotFoundException,
    UnknownObjectException, GithubException, _handle_http_error
)
from github.api.endpoints import (
    REPO_URL, BRANCH_URL, TREE_URL, BLOB_URL, RATE_LIMIT_URL,
    USER_URL, ORG_URL, ISSUES_URL, ISSUE_DETAIL_URL, RAW_FILE_BY_BRANCH
)
from github.models import GitHubUser, Repository, RateLimitResponse, RepoTreeModel, ProjectFile

# load_dotenv()
# GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

T = TypeVar('T')

class RateLimitState:
    def __init__(self):
        self.remaining: Optional[int] = None
        self.limit: Optional[int] = None
        self.reset: Optional[int] = None
        self.last_updated: float = 0.0

    def update_rate_state(self, headers: dict):
        self.remaining = int(headers.get('X-RateLimit-Remaining', 0))
        self.limit = int(headers.get('X-RateLimit-Limit', 0))
        self.reset = int(headers.get('X-RateLimit-Reset', 0))
        self.last_updated = time.time()

    @property
    def should_throttle(self) -> bool:
        if self.remaining is None or self.reset is None:
            return False
        return self.remaining <= 0 and time.time() < self.reset

class RequestHandler:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.rate_limit = RateLimitState()
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Client',
        }
        if self.token:
            self.headers['Authorization'] = f'token {self.token}'

    def _handle_rate_limit(self):
        """Check and handle rate limiting"""
        if self.rate_limit.should_throttle:
            print(f"Rate limit exceeded. Try again after {self.rate_limit.reset}")
            time.sleep(max(0, self.rate_limit.reset - time.time()))

    def _validate_response(self, response: dict, model: Type[T]) -> T:
        """Data validation against pydantic models"""
        try:
            return model(**response)
        except ValidationError as e:
            print(f"Validation Error: {e}")
            raise

    def _make_request(self, url: str, model: Type[T], params: Optional[Dict[str, Any]] = None) -> T:
        """Make a validated API request to the GitHub API."""
        self._handle_rate_limit()

        try:
            res = requests.get(url, headers=self.headers, params=params)
            res.raise_for_status()
            self.rate_limit.update_rate_state(res.headers)
            return self._validate_response(res.json(), model)

        except HTTPError as e:
            _handle_http_error(e, res)
        except RequestException as e:
            print(f"Request failed: {e}")
            raise

    def get_rate_limit(self) -> RateLimitResponse:
        """Fetch the current rate limit status."""
        return self._make_request(RATE_LIMIT_URL, model=RateLimitResponse)

    def get_user(self, user: str) -> GitHubUser:
        """Fetch user details."""
        user_url = USER_URL.format(user=user)
        return self._make_request(user_url, model=GitHubUser)

    def get_repo(self, user: str, repo: str) -> Repository:
        """Fetch repository details."""
        repo_url = REPO_URL.format(user=user, repo=repo)
        return self._make_request(repo_url, model=Repository)
    
    def get_repo_tree(self, user: str, repo: str, branch: str) -> RepoTreeModel:
        """Fetch Repo Tree"""
        tree_url = TREE_URL.format(user=user, repo=repo, branch=branch)
        print(tree_url)
        return self._make_request(tree_url, model=RepoTreeModel)
    
    def get_raw_file(self, user: str, repo: str, branch: str, path: str) -> ProjectFile:
        file_url = RAW_FILE_BY_BRANCH.format(user=user, repo=repo, branch=branch, path=path)
        self._handle_rate_limit()

        try:
            res = requests.get(file_url, headers=self.headers)
            res.raise_for_status()
            self.rate_limit.update_rate_state(res.headers)
            return ProjectFile(file_content=res.text)

        except HTTPError as e:
            _handle_http_error(e, res)
        except RequestException as e:
            print(f"Request failed: {e}")
            raise
        

# if __name__ == "__main__":
#     handler = RequestHandler(token=GITHUB_TOKEN)

#     try:
#         rate_limit = handler.get_rate_limit()
#         print(f"Remaining requests: {rate_limit.rate.remaining}")
#         repo_details = handler.get_repo("octocat", "Hello-World")
#         print(repo_details.model_dump(), "Type: ", type(repo_details))
#         tree_details = handler.get_repo_tree(user="aijurist", repo="aijurist", branch="master")
#         paths = tree_details.blobs
#         print(tree_details.blobs, f"Type: {type(tree_details)}")
#         # for i in paths:
#         print(handler.get_raw_file(user="aijurist", repo="aijurist", branch="master", path='forms/contact.php'))

#     except RateLimitExceededException:
#         print("Rate limit exceeded. Please wait before making more requests.")
#     except NotFoundException:
#         print("The requested resource was not found.")
#     except BadCredentialsException:
#         print("Invalid credentials. Please check your token.")
#     except Exception as e:
#         print(f"An unexpected error occurred: {e}")