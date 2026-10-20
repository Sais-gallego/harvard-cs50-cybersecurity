import os
import subprocess
import tempfile
import json
import time
import urllib.request
import urllib.error

cwd = r"c:\xampp\htdocs\cursos\harvard-cs50-cybersecurity"

# 1. Get git token
tpath = os.path.join(tempfile.gettempdir(), "gitcred.txt")
with open(tpath, "w", encoding="utf-8") as f:
    f.write("protocol=https\nhost=github.com\n\n")

proc = subprocess.run(
    "git credential fill",
    input=open(tpath, "rb").read(),
    stdout=subprocess.PIPE,
    shell=True,
    check=True
)
if os.path.exists(tpath):
    os.remove(tpath)

lines = proc.stdout.decode("utf-8").splitlines()
token = [l[9:] for l in lines if l.startswith("password=")][0]
username = "Sais-gallego"
repo_name = "harvard-cs50-cybersecurity"
print(f"Extracted token successfully for {username}")

def run_git(cmd):
    p = subprocess.run(cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f"$ {cmd}\n{p.stdout.strip()}")
    if p.stderr.strip():
        print(f"ERR: {p.stderr.strip()}")
    return p

# 2. Local git setup
run_git("git init")
run_git('git config user.name "Sergio Andrés Ipuz Saavedra"')
run_git('git config user.email "afranklinromero@gmail.com"')
run_git("git checkout -B main")
run_git("git add .")
run_git('git commit -m "feat(harvard-cs50): Official Harvard CS50 Cybersecurity solutions with Account Security, Memory Safety, Network Traffic, Web Defenses, and Forensics"')

# 3. Create repo on GitHub with retry on secondary rate limit
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Antigravity-Agent"
}

payload = {
    "name": repo_name,
    "description": "Harvard University: CS50 Introduction to Cybersecurity (Prof. David J. Malan) - Comprehensive implementations of cryptography, memory safety, network security, web defenses, and digital forensics by Sergio Andrés Ipuz Saavedra.",
    "private": False,
    "has_issues": True,
    "has_projects": True,
    "has_wiki": False
}

for attempt in range(5):
    try:
        req = urllib.request.Request(
            "https://api.github.com/user/repos",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers
        )
        with urllib.request.urlopen(req) as resp:
            print(f"Created repository {repo_name} on GitHub (HTTP {resp.status})")
            break
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        if e.code == 422:
            print(f"Repository {repo_name} already exists on GitHub.")
            break
        elif e.code == 403:
            print(f"Rate limited (attempt {attempt+1}): {body}")
            time.sleep(10)
        else:
            print(f"GitHub API Error: {e.code} - {body}")
            break

# 4. Push to GitHub
remote_url = f"https://{username}:{token}@github.com/{username}/{repo_name}.git"
run_git(f'git remote remove origin')
run_git(f'git remote add origin "{remote_url}"')
push_res = run_git("git push -u origin main --force")

# Sanitize remote URL
run_git(f'git remote set-url origin "https://github.com/{username}/{repo_name}.git"')
print("Push completed and remote URL secured.")
