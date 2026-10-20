import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptocore.csprng import generate_random_bytes  # noqa: E402

CHUNK_SIZE = 4096


def generate_file(path, total_size: int, chunk_size: int = CHUNK_SIZE) -> int:
    written = 0
    with open(path, "wb") as f:
        while written < total_size:
            chunk = generate_random_bytes(min(chunk_size, total_size - written))
            f.write(chunk)
            written += len(chunk)
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Генерирует файл случайных данных для тестов NIST STS.")
    parser.add_argument("--size-mb", type=int, default=10, help="Размер файла в мегабайтах (по умолчанию 10).")
    parser.add_argument("--output", default="nist_test_data.bin", help="Путь к выходному файлу.")
    args = parser.parse_args(argv)

    written = generate_file(args.output, args.size_mb * 1_000_000)
    print(f"Сгенерировано {written} байт в '{args.output}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
