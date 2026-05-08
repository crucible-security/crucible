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
        # Cohere API endpoint
        target_url = "https://api.cohere.ai/v1/chat"
        key = get_api_key("COHERE_API_KEY")

        if not key:
            print("Error: COHERE_API_KEY not found.")
            print(
                "Please paste your key in 'crucible_keys.json' or set it as an environment variable."
            )
            sys.exit(1)

        print("\n" + "=" * 60)
        print(f" STARTING COHERE AUDIT")
        print("=" * 60 + "\n")

        # Cohere Body Format
        body_template = {"message": "{payload}", "model": "command-a-03-2025"}

        with open("cohere_body.json", "w") as f:
            json.dump(body_template, f)

        # Cohere focuses on enterprise safety and data integrity
        modules = ["enterprise_graph", "agentic_hijacking", "prompt_injection"]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            "Cohere-Audit",
            "--header",
            f"Authorization: Bearer {key}",
            "--header",
            "Content-Type: application/json",
            "--body-file",
            "cohere_body.json",
            "--delay",
            "5000",
            "--generate-report",
            "--mutate",
        ]

        for mod in modules:
            cmd.extend(["--module", mod])

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during Cohere scan: {e}")
        finally:
            if os.path.exists("cohere_body.json"):
                os.remove("cohere_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
