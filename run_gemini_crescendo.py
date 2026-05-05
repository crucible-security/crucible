import os
import subprocess
import sys
import json


def get_api_key(key_name):
    # Try API_KEY_HERE.txt specifically for Gemini
    try:
        simple_file = os.path.join(os.path.dirname(__file__), "API_KEY_HERE.txt")
        if os.path.exists(simple_file):
            with open(simple_file, "r") as f:
                key = f.read().strip()
                if key and "PASTE_YOUR" not in key:
                    return key
    except Exception:
        pass

    # Try environment variable
    key = os.getenv(key_name)
    if key:
        return key

    # Try crucible_keys.json
    try:
        keys_file = os.path.join(os.path.dirname(__file__), "crucible_keys.json")
        if os.path.exists(keys_file):
            with open(keys_file, "r") as f:
                keys = json.load(f)
                key = keys.get(key_name)
                if key and "PASTE_YOUR" not in key:
                    return key
    except Exception:
        pass

    return None


def main():
    try:
        # Google Gemini AI Studio endpoint
        model = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
        key = get_api_key("GEMINI_API_KEY")

        if not key:
            print("Error: GEMINI_API_KEY not found.")
            sys.exit(1)

        target_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

        print("\n" + "=" * 60)
        print(f" STARTING ADVANCED GEMINI CRESCENDO AUDIT ({model})")
        print("=" * 60 + "\n")

        # We don't need a body-file for multi-turn as the engine handles it
        # but the CLI might require something to start.
        # Actually, the MultiTurnEngine ignores the body template if it's Gemini.

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            f"Gemini-Crescendo-Audit",
            "--strategy",
            "multi-turn",
            "--delay",
            "3000",  # Higher delay for multi-turn stability
            "--generate-report",
            "--verbose",  # Multi-turn is more interesting to see live
        ]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during Gemini Crescendo scan: {e}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
