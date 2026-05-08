import os
import subprocess
import sys
import json


def get_api_key(key_name):
    # Try environment variable first
    key = os.getenv(key_name)
    if key:
        return key

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

    # Try crucible_keys.json fallback
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
        # gemini-flash-latest is the stable choice in 2026
        model = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
        key = get_api_key("GEMINI_API_KEY")

        if not key:
            print("Error: GEMINI_API_KEY not found.")
            print(
                "Please paste your key in 'crucible_keys.json' or set it as an environment variable."
            )
            sys.exit(1)

        target_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

        print("\n" + "=" * 60)
        print(f" STARTING GOOGLE GEMINI AUDIT ({model})")
        print("=" * 60 + "\n")

        # Google Gemini Body Format
        body_template = {"contents": [{"parts": [{"text": "{payload}"}]}]}

        with open("gemini_body.json", "w") as f:
            json.dump(body_template, f)

        # Focus on high-value modules for Google VRP
        modules = [
            "browser_agent",
            "enterprise_graph",
            "agentic_hijacking",
            "jailbreaks",
        ]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            f"Gemini-{model}-Audit",
            "--header",
            "Content-Type: application/json",
            "--body-file",
            "gemini_body.json",
            "--delay",
            "2000",
            "--generate-report",
            "--mutate",
        ]

        for mod in modules:
            cmd.extend(["--module", mod])

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during Gemini scan: {e}")
        finally:
            if os.path.exists("gemini_body.json"):
                os.remove("gemini_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
