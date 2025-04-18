import os
import requests
import re

# ========== CONFIG ==========
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or "your_token_here"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Generic API Key": r"(?i)(api|apikey|access_token|auth_token)[\"'=:\s]+[\"']?[a-z0-9\-_]{16,45}[\"']?",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "S3 Bucket URL": r"https?://s3[\.-][a-z0-9-]+\.amazonaws\.com/[^\s\"']+"
}


# ========== FUNCTIONS ==========

def get_repos(org):
    url = f"https://api.github.com/orgs/{org}/repos?per_page=100"
    res = requests.get(url, headers=HEADERS)
    if res.status_code != 200:
        print(f"[!] Failed to fetch repos: {res.status_code}")
        return []
    return res.json()


def get_files(org, repo):
    url = f"https://api.github.com/repos/{org}/{repo}/git/trees/HEAD?recursive=1"
    res = requests.get(url, headers=HEADERS)
    if res.status_code != 200:
        return []
    tree = res.json().get("tree", [])
    return [item['path'] for item in tree if item['type'] == 'blob']


def fetch_file(org, repo, path):
    url = f"https://raw.githubusercontent.com/{org}/{repo}/HEAD/{path}"
    res = requests.get(url)
    return res.text if res.status_code == 200 else ""


def scan(content, domain):
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for type_, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                findings.append((i, type_))
        if re.search(rf"[a-zA-Z0-9_.+-]+@{re.escape(domain)}", line):
            findings.append((i, "Email (target domain)"))
        if re.search(rf"[a-zA-Z0-9_.+-]+@{re.escape(domain)}:\S+", line):
            findings.append((i, "Email:Password (target domain)"))
    return findings


def risk_score(findings):
    score = 0
    for _, type_ in findings:
        if "Password" in type_ or "JWT" in type_:
            score += 5
        elif "AWS" in type_ or "Slack" in type_ or "API" in type_:
            score += 4
        elif "Email" in type_:
            score += 2
        else:
            score += 1
    return score


# ========== MAIN ==========

def main():
    org = input("Enter GitHub organization name: ").strip()
    domain = input("Enter target domain (e.g. example.com): ").strip()

    print(f"\n[*] Scanning organization: {org}...\n")
    repos = get_repos(org)
    total = 0

    for repo in repos:
        repo_name = repo['name']
        files = get_files(org, repo_name)

        for file_path in files:
            content = fetch_file(org, repo_name, file_path)
            if not content:
                continue

            findings = scan(content, domain)
            if findings:
                total += len(findings)
                for line_no, secret_type in findings:
                    url = f"https://github.com/{org}/{repo_name}/blob/HEAD/{file_path}#L{line_no}"
                    print(f"[!] Secret Found: {secret_type}")
                    print(f"    ↪ Repo: {repo_name}")
                    print(f"    ↪ File: {file_path}")
                    print(f"    ↪ Line: {line_no}")
                    print(f"    ↪ Link: {url}")
                print(f"    → Risk Score: {risk_score(findings)}\n")

    print(f"[*] Total Number of Leaked Secrets detected: {total}")


if __name__ == "__main__":
    main()
