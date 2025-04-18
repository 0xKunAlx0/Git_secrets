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
