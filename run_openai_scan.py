import os
import subprocess
import sys
import json


def main():
    try:
        # 1. Extract the API key
        if not os.path.exists("openai_key.txt"):
            print("Error: openai_key.txt not found.")
            sys.exit(1)

        with open("openai_key.txt", "r") as f:
            lines = f.readlines()
            key = None
            for line in lines:
                if line.strip().startswith("sk-proj-"):
                    key = line.strip()
                    break

        if not key:
            print("Error: Could not find a valid sk-proj- key in openai_key.txt")
            sys.exit(1)

        # 2. Create the body template file (This bypasses shell escaping issues)
        body_template = {
            "model": "{model}",
            "messages": [{"role": "user", "content": "{payload}"}],
        }
        with open("openai_body.json", "w") as f:
            json.dump(body_template, f)

        models = ["gpt-4o-mini", "gpt-4o", "o1-preview"]

        for model in models:
            print("\n" + "=" * 60)
            print(f" STARTING SCAN FOR MODEL: {model}")
            print("=" * 60 + "\n")

            # Prepare the specific body for this model by replacing {model} in the file
            # Actually, Crucible will handle {payload}, but we need to set the model name.
            # We'll create a model-specific body file.
            model_body_path = f"body_{model}.json"
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
                "https://api.openai.com/v1/chat/completions",
                "--name",
                f"OpenAI-{model}",
                "--header",
                f"Authorization: Bearer {key}",
                "--body-file",
                model_body_path,
                "--delay",
                "2500",
                "--verbose",
                "--generate-report",
            ]

            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error scanning {model}: {e}")
            finally:
                # Clean up model-specific body file
                if os.path.exists(model_body_path):
                    os.remove(model_body_path)

        # Final cleanup
        if os.path.exists("openai_body.json"):
            os.remove("openai_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
