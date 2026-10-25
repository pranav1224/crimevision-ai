"""
CrimeVision AI - Direct GitHub Upload Utility
Allows uploading the complete project to GitHub even if Git is not installed
on the system, using the official GitHub REST API.
"""

import os
import sys
import base64
import json
import urllib.request
import urllib.error

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def upload_project(github_token: str, repo_name: str = "crimevision-ai", username: str = None):
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CrimeVisionAI-Uploader"
    }

    # 1. Fetch authenticated user if not provided
    if not username:
        try:
            req = urllib.request.Request("https://api.github.com/user", headers=headers)
            with urllib.request.urlopen(req) as response:
                user_data = json.loads(response.read().decode())
                username = user_data["login"]
                print(f"Authenticated as GitHub user: {username}")
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    # 2. Create public repo if it does not exist
    create_repo_url = "https://api.github.com/user/repos"
    payload = {
        "name": repo_name,
        "description": "CrimeVision AI - Intelligent Multimodal Forensic Analysis Platform (Skill Wallet Capstone Project 2)",
        "private": False,
        "auto_init": False
    }
    try:
        req = urllib.request.Request(create_repo_url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req) as resp:
            print(f"Successfully created GitHub repository: https://github.com/{username}/{repo_name}")
    except urllib.error.HTTPError as e:
        if e.code == 422:
            print(f"Repository '{repo_name}' already exists. Uploading files...")
        else:
            print(f"Error creating repository: {e}")
            return False

    # 3. Walk through project directory and upload files
    exclude_dirs = {"__pycache__", ".venv", ".git"}
    uploaded_count = 0

    for root, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".pyc") or f == "upload_to_github.py" or f.endswith(".log"):
                continue
            abs_path = os.path.join(root, f)
            rel_path = os.path.relpath(abs_path, PROJECT_DIR).replace("\\", "/")

            with open(abs_path, "rb") as file_handle:
                content_bytes = file_handle.read()
            b64_content = base64.b64encode(content_bytes).decode("utf-8")

            # Check if file exists to get SHA for update
            file_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{rel_path}"
            sha = None
            try:
                get_req = urllib.request.Request(file_url, headers=headers)
                with urllib.request.urlopen(get_req) as get_resp:
                    existing_data = json.loads(get_resp.read().decode())
                    sha = existing_data.get("sha")
            except Exception:
                pass

            put_payload = {
                "message": f"feat: upload {rel_path} for CrimeVision AI",
                "content": b64_content
            }
            if sha:
                put_payload["sha"] = sha

            put_req = urllib.request.Request(
                file_url,
                data=json.dumps(put_payload).encode(),
                headers=headers,
                method="PUT"
            )
            try:
                with urllib.request.urlopen(put_req) as put_resp:
                    uploaded_count += 1
                    print(f"[{uploaded_count}] Uploaded: {rel_path}")
            except Exception as e:
                print(f"Failed to upload {rel_path}: {e}")

    print("\n" + "="*60)
    print(f"SUCCESS! Repository is live at: https://github.com/{username}/{repo_name}")
    print("="*60)
    return True


if __name__ == "__main__":
    token = os.environ.get("GITHUB_TOKEN")
    if not token and len(sys.argv) > 1:
        token = sys.argv[1]

    if not token:
        print("Usage:")
        print("  1. Create a GitHub Personal Access Token at https://github.com/settings/tokens (select 'repo' scope)")
        print("  2. Run: python upload_to_github.py <YOUR_GITHUB_TOKEN>")
    else:
        upload_project(token)
