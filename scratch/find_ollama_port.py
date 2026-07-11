import subprocess
try:
    out = subprocess.check_output('netstat -ano', shell=True).decode('utf-8')
    for line in out.splitlines():
        if 'LISTENING' in line:
            parts = line.split()
            if len(parts) >= 5:
                pid = parts[-1]
                try:
                    task = subprocess.check_output(f'tasklist /FI "PID eq {pid}"', shell=True).decode('utf-8')
                    if 'ollama' in task.lower():
                        print(f"Ollama connection: {line.strip()}")
                except Exception:
                    pass
except Exception as e:
    print("Error:", e)
