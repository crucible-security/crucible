"""
Poll GitHub Actions for the latest run result.

Uses GITHUB_TOKEN env var for authenticated requests (5000 req/hr).
Falls back to unauthenticated (60 req/hr) if no token found.
Polls with exponential backoff to avoid exhausting rate limits.
"""

import os
import sys
import time

import httpx

REPO = "crucible-security/crucible"
BASE_URL = f"https://api.github.com/repos/{REPO}"

token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
if token:
    headers["Authorization"] = f"Bearer {token}"
    print("Using authenticated GitHub API requests.")
else:
    print("No GITHUB_TOKEN found — using unauthenticated (60 req/hr limit).")

wait = 15  # start with 15s, exponential backoff up to 60s

print("Polling GitHub Actions API...")
for attempt in range(40):
    try:
        resp = httpx.get(f"{BASE_URL}/actions/runs", params={"per_page": 1}, headers=headers)

        if resp.status_code == 403:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", 0))
            reset_in = max(reset_ts - int(time.time()), 60)
            print(f"Rate limited. Waiting {reset_in}s for reset...")
            time.sleep(reset_in)
            continue

        resp.raise_for_status()
        data = resp.json()
        run = data["workflow_runs"][0]

        if run["status"] == "completed":
            print(f"\nRun #{run['run_number']}: {run['head_commit']['message'][:60]}")
            print(f"Status   : {run['status']}")
            print(f"Conclusion: {run['conclusion']}")
            print(f"URL      : {run['html_url']}")

            if run["conclusion"] != "success":
                # Fetch failed jobs
                jobs_resp = httpx.get(run["jobs_url"], headers=headers)
                jobs_data = jobs_resp.json()
                print("\nFailed jobs:")
                for job in jobs_data.get("jobs", []):
                    if job["conclusion"] != "success":
                        print(f"  ✗ {job['name']}")
                sys.exit(1)

            print("\n✅ CI PASSED!")
            sys.exit(0)

        print(f"  [{attempt + 1}] Still {run['status']}... (waiting {wait}s)")

    except Exception as e:
        print(f"  Error: {e}")

    time.sleep(wait)
    wait = min(wait * 1.5, 60)  # cap at 60s

print("Timed out waiting for CI to complete.")
sys.exit(1)
