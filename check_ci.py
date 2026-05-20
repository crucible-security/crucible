import httpx
import time
import sys

url = 'https://api.github.com/repos/crucible-security/crucible/actions/runs'
print('Polling GitHub Actions API...')
for _ in range(60):
    try:
        resp = httpx.get(url, params={'per_page': 1})
        resp.raise_for_status()
        data = resp.json()
        run = data['workflow_runs'][0]
        if run['status'] == 'completed':
            print(f"Conclusion: {run['conclusion']}")
            if run['conclusion'] != 'success':
                print(f"URL: {run['html_url']}")
                # Get the failed jobs
                jobs_url = run['jobs_url']
                jobs_resp = httpx.get(jobs_url)
                jobs_data = jobs_resp.json()
                for job in jobs_data.get('jobs', []):
                    if job['conclusion'] != 'success':
                        print(f"Job Failed: {job['name']}")
                sys.exit(1)
            sys.exit(0)
        print(f"Still {run['status']}...")
    except Exception as e:
        print(f'Error: {e}')
    time.sleep(10)
print('Timed out waiting for completion')
sys.exit(1)
