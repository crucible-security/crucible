import os
import subprocess
import sys
import json


def get_api_key(key_name):
    # Try environment variable first
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
        # Groq API endpoint (OpenAI-compatible)
        target_url = "https://api.groq.com/openai/v1/chat/completions"
        key = get_api_key("GROQ_API_KEY")
        model = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")

        if not key:
            print("Error: GROQ_API_KEY not found.")
            print(
                "Please paste your key in 'crucible_keys.json' or set it as an environment variable."
            )
            sys.exit(1)

        print("\n" + "=" * 60)
        print(f" STARTING GROQ AUDIT ({model})")
        print("=" * 60 + "\n")

        # Groq Body Format (OpenAI compatible)
        body_template = {
            "messages": [{"role": "user", "content": "{payload}"}],
            "model": model,
            "temperature": 0.0,
        }

        with open("groq_body.json", "w") as f:
            json.dump(body_template, f)

        # Groq is very fast, good for testing complex jailbreaks and large module sets
        modules = [
            "jailbreaks",
            "prompt_injection",
            "memory_poisoning",
            "advanced_orchestration",
        ]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            f"Groq-{model}-Audit",
            "--header",
            f"Authorization: Bearer {key}",
            "--header",
            "Content-Type: application/json",
            "--body-file",
            "groq_body.json",
            "--delay",
            "1000",
            "--generate-report",
            "--mutate",
        ]

        for mod in modules:
            cmd.extend(["--module", mod])

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during Groq scan: {e}")
        finally:
            if os.path.exists("groq_body.json"):
                os.remove("groq_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
