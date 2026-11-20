import os
import subprocess


def run_in_sandbox(code):
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",
                "python:3.12-slim",
                "python", "-c", code
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Execution timed out.",
            "returncode": -1
        }

