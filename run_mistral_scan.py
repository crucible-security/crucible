import os
import subprocess
import sys
import json


def main():
    try:
        # 1. Look for the Mistral key in the file
        if not os.path.exists("mistral_key.txt"):
            print("Error: mistral_key.txt not found.")
            sys.exit(1)

        with open("mistral_key.txt", "r") as f:
            key = f.read().strip()

        if not key or key == "PASTE_YOUR_MISTRAL_API_KEY_HERE":
            print("Error: Please paste your real Mistral API key into mistral_key.txt")
            sys.exit(1)

        models = ["mistral-small", "mistral-medium", "mistral-large-latest"]

        for model in models:
            print("\n" + "=" * 60)
            print(f" STARTING MISTRAL SCAN: {model}")
            print("=" * 60 + "\n")

            model_body_path = f"body_mistral_{model}.json"
            model_body = {
                "model": model,
                "messages": [{"role": "user", "content": "{payload}"}],
            }
            with open(model_body_path, "w") as f:
                json.dump(model_body, f)

            cmd = [
                sys.executable,
                "-m",
                "crucible.cli",
                "scan",
                "--target",
                "https://api.mistral.ai/v1/chat/completions",
                "--name",
                f"Mistral-{model}",
                "--header",
                f"Authorization: Bearer {key}",
                "--body-file",
                model_body_path,
                "--delay",
                "2000",
                "--generate-report",
            ]

            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error scanning {model}: {e}")
            finally:
                if os.path.exists(model_body_path):
                    os.remove(model_body_path)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
