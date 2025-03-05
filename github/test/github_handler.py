from github.api import github_api_handler, APIConfig, GithubException
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

async def main():
    config = APIConfig(
        user="octocat",
        repo="Hello-World",
        branch="master",
        # path="README",
        token=os.getenv('GITHUB_TOKEN')
    )

    try:
        results = await github_api_handler(config)
        
        print("\nRate Limit:", results.get('rate_limit'))
        print("\nUser Details:", results.get('user'))
        print("\nRepo Details:", results.get('repo'))
        
        if "tree" in results:
            print("\nTree details:", results["tree"])
            print("\n")
        
        if "files" in results:
            for path, content in results["files"].items():
                print(f"File Path: {path}\tContent:{content}\n")
        
    except GithubException as e:
        print(f"GitHub Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
