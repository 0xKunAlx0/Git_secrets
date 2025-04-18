# 🔍 GitHub Secret Scanner

This tool scans public repositories of a GitHub organization to detect **hardcoded secrets**, such as AWS keys, API tokens, JWTs, S3 URLs, and more.

## 🚀 Features
- Supports GitHub API using token
- Detects common secrets with regex
- Provides risk score per finding
- Outputs full GitHub file links with line numbers
- Supports custom domain (for emails)

## 🧪 Detected Secrets
- AWS Access Keys
- Slack Tokens
- Google API Keys
- JWTs
- Generic API/Access Tokens
- Emails & Passwords for custom domain
- Amazon S3 URLs

## 🛠️ Requirements

- Python 3.7+
- GitHub Personal Access Token

Install dependencies:

```bash
pip install -r requirements.txt


🔑 GitHub Token
Create a token from https://github.com/settings/tokens

Enable scopes:
public_repo (only needed)

Set it as an environment variable:
export GITHUB_TOKEN="your_token_here"

🧭 Usage
python github_secret_scanner.py

Follow the prompt:
Enter GitHub organization name: my-org
Enter target domain (e.g. example.com): example.com

📦 Output Format
[!] Secret Found: AWS Access Key
    ↪ Repo: billing-api
    ↪ File: config.py
    ↪ Line: 42
    ↪ Link: https://github.com/my-org/billing-api/blob/HEAD/config.py#L42
    → Risk Score: 4
