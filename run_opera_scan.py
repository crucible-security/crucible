import os
import subprocess
import sys
import json


def main():
    try:
        # Opera Aria endpoint (example placeholder)
        target_url = os.getenv(
            "OPERA_ARIA_ENDPOINT", "https://api.opera.com/v1/aria/chat"
        )
        key = os.getenv("OPERA_API_KEY")

        if not key:
            print("Error: OPERA_API_KEY environment variable not set.")
            print("Usage: OPERA_API_KEY=sk-xxx python run_opera_scan.py")
            sys.exit(1)

        print("\n" + "=" * 60)
        print(f" STARTING OPERA ARIA AUDIT")
        print("=" * 60 + "\n")

        body_template = {
            "messages": [{"role": "user", "content": "{payload}"}],
            "stream": False,
        }

        with open("opera_body.json", "w") as f:
            json.dump(body_template, f)

        # Specialized modules for Browser Agents
        modules = ["browser_agent", "jailbreaks", "prompt_injection"]

        cmd = [
            sys.executable,
            "-m",
            "crucible.cli",
            "scan",
            "--target",
            target_url,
            "--name",
            "Opera-Aria-Audit",
            "--header",
            f"Authorization: Bearer {key}",
            "--body-file",
            "opera_body.json",
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
            print(f"Error during Opera scan: {e}")
        finally:
            if os.path.exists("opera_body.json"):
                os.remove("opera_body.json")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
