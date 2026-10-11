import os
import subprocess
import sys
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")

KEY = "000102030405060708090a0b0c0d0e0f"


def run_cryptocore(*args, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "cryptocore", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=cwd,
    )
