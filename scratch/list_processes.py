import subprocess
out = subprocess.check_output("tasklist", shell=True).decode('utf-8')
for line in out.splitlines():
    if 'ollama' in line.lower():
        print(line.strip())
