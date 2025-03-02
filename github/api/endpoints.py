BASE_URL = "https://api.github.com"
RAW_FILE_URL = "https://raw.githubusercontent.com"
DEFAULT_STATUS_URL = "https://status.github.com"

#Repo relate
REPO_URL = f"{BASE_URL}/repos/{{user}}/{{repo}}" 
BRANCH_URL = f"{REPO_URL}/branches/{{branch}}" 
TREE_URL = f"{REPO_URL}/git/trees/{{branch}}?recursive=1" 

# blob file related
BLOB_URL = f"{REPO_URL}/git/blobs/{{sha}}" 

# user related 
USER_URL = f"{BASE_URL}/users/{{user}}"
ORG_URL = f"{BASE_URL}/orgs/{{org}}"

# Issues
ISSUES_URL = f"{REPO_URL}/issues"
ISSUE_DETAIL_URL = f"{ISSUES_URL}/{{issue_number}}" 

# Rate limit status
RATE_LIMIT_URL = f"{BASE_URL}/rate_limit"

RAW_FILE_BY_BRANCH = f"{RAW_FILE_URL}/{{user}}/{{repo}}/{{branch}}/{{path}}"
