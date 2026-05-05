import os
import subprocess
import sys
import json


def main():
    try:
        # Glean Assistant endpoint (example placeholder)
        target_url = os.getenv("GLEAN_ENDPOINT", "https://api.glean.com/v1/chat")
        key = os.getenv("GLEAN_API_KEY")

        if not key:
            print("Error: GLEAN_API_KEY environment variable not set.")
            print("Usage: GLEAN_API_KEY=xxx python run_glean_scan.py")
            sys.exit(1)

        print("\n" + "=" * 60)
        print(f" STARTING GLEAN ASSISTANT AUDIT")
        print("=" * 60 + "\n")

        body_template = {
            "query": "{payload}",
            "stream": False,
            "source": "crucible_audit",
        }

        with open("glean_body.json", "w") as f:
            json.dump(body_template, f)

        # Specialized modules for Enterprise Search Assistants
        modules = ["enterprise_graph", "agentic_hijacking", "memory_poisoning"]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            "Glean-Assistant-Audit",
            "--header",
            f"Authorization: Bearer {key}",
            "--body-file",
            "glean_body.json",
            "--delay",
            "1500",
            "--generate-report",
            "--mutate",
        ]

        for mod in modules:
            cmd.extend(["--module", mod])

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during Glean scan: {e}")
        finally:
            if os.path.exists("glean_body.json"):
                os.remove("glean_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
