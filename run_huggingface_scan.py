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
        # Hugging Face Inference API
        model_id = os.getenv("HF_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.3")
        target_url = f"https://api-inference.huggingface.co/models/{model_id}"
        key = get_api_key("HF_API_KEY")

        if not key:
            print("Error: HF_API_KEY not found.")
            print(
                "Please paste your key in 'crucible_keys.json' or set it as an environment variable."
            )
            sys.exit(1)

        print("\n" + "=" * 60)
        print(f" STARTING HUGGING FACE AUDIT ({model_id})")
        print("=" * 60 + "\n")

        # Hugging Face Inference API Format
        body_template = {
            "inputs": "{payload}",
            "parameters": {"return_full_text": False},
        }

        with open("hf_body.json", "w") as f:
            json.dump(body_template, f)

        # Focus on infrastructure and model-specific vectors
        modules = ["infrastructure_escalation", "jailbreaks", "prompt_injection"]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            f"HF-{model_id.split('/')[-1]}-Audit",
            "--header",
            f"Authorization: Bearer {key}",
            "--header",
            "Content-Type: application/json",
            "--body-file",
            "hf_body.json",
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
            print(f"Error during Hugging Face scan: {e}")
        finally:
            if os.path.exists("hf_body.json"):
                os.remove("hf_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
