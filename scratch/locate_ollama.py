import os
from pathlib import Path

paths = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe",
    Path("C:/Program Files/Ollama/ollama.exe"),
    Path("C:/Program Files (x86)/Ollama/ollama.exe"),
]

found = False
for p in paths:
    if p.exists():
        print(f"FOUND: {p}")
        found = True

if not found:
    print("Ollama not found in standard paths.")
