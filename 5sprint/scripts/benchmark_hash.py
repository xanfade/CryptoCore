"""Сравнение скорости собственных реализаций SHA-256 и SHA3-256 с hashlib и системным sha256sum."""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptocore.hash import ALGORITHMS  # noqa: E402

REFERENCE = {"sha256": hashlib.sha256, "sha3-256": hashlib.sha3_256}


def timed(function):
    start = time.perf_counter()
    result = function()
    return time.perf_counter() - start, result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes-mb", type=float, nargs="+", default=[0.1, 1, 5])
    args = parser.parse_args(argv)

    sha256sum = shutil.which("sha256sum")
    print(f"{'алгоритм':10s} {'размер, МБ':>10s} {'cryptocore, с':>14s} {'hashlib, с':>11s} "
          f"{'sha256sum, с':>13s} {'МБ/с (наш)':>11s} {'медленнее в':>12s}")

    with tempfile.TemporaryDirectory() as folder:
        for size_mb in args.sizes_mb:
            data = os.urandom(int(size_mb * 1_000_000))
            path = os.path.join(folder, "data.bin")
            with open(path, "wb") as f:
                f.write(data)

            for name, cls in ALGORITHMS.items():
                ours, digest = timed(lambda: cls(data).hexdigest())
                ref, expected = timed(lambda: REFERENCE[name](data).hexdigest())
                assert digest == expected, f"{name}: хеш не совпал с hashlib"

                system = "-"
                if name == "sha256" and sha256sum:
                    spent, _ = timed(lambda: subprocess.run([sha256sum, path], capture_output=True))
                    system = f"{spent:.4f}"

                speed = size_mb / ours
                ratio = ours / ref if ref > 0 else float("inf")
                print(f"{name:10s} {size_mb:10.1f} {ours:14.3f} {ref:11.5f} {system:>13s} "
                      f"{speed:11.2f} {ratio:12.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
