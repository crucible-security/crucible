import httpx

run_id = 26147819047
url = f'https://api.github.com/repos/crucible-security/crucible/actions/runs/{run_id}/jobs'
resp = httpx.get(url)
data = resp.json()

for job in data['jobs']:
    if job['conclusion'] != 'success':
        print(f"Job: {job['name']} (ID: {job['id']})")
        log_url = f"https://api.github.com/repos/crucible-security/crucible/actions/jobs/{job['id']}/logs"
        try:
            log_resp = httpx.get(log_url, follow_redirects=True)
            if log_resp.status_code == 200:
                logs = log_resp.text
                for line in logs.split('\n'):
                    if 'error' in line.lower() or 'failed' in line.lower() or 'mypy' in line.lower() or 'ruff' in line.lower():
                        print(line)
        except Exception as e:
            print(f'Could not fetch logs: {e}')
        break
