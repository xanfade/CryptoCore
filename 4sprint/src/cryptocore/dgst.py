import argparse
import sys
from pathlib import Path

from cryptocore.hash import ALGORITHMS

CHUNK_SIZE = 8192
STDIN_NAME = "-"


def build_dgst_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Вычисляет хеш файла (формат вывода как у sha256sum: ХЕШ  ФАЙЛ).",
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=sorted(ALGORITHMS),
        help="Алгоритм хеширования: sha256 или sha3-256.",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Путь к входному файлу или '-' для чтения из стандартного ввода.",
    )
    parser.add_argument(
        "--output",
        required=False,
        default=None,
        help="Записать результат в файл вместо вывода в stdout.",
    )
    return parser


def hash_stream(stream, algorithm: str) -> str:
    hasher = ALGORITHMS[algorithm]()
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def run_dgst(argv) -> int:
    parser = build_dgst_parser()
    args = parser.parse_args(argv)

    try:
        if args.input == STDIN_NAME:
            digest = hash_stream(sys.stdin.buffer, args.algorithm)
        else:
            if not Path(args.input).is_file():
                parser.error(f"входной файл не найден: {args.input}")
            with open(args.input, "rb") as f:
                digest = hash_stream(f, args.algorithm)
    except OSError as exc:
        print(f"cryptocore: ошибка: не удалось прочитать входной файл: {exc}", file=sys.stderr)
        return 1

    line = f"{digest}  {args.input}\n".encode("utf-8")

    if args.output is None:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        return 0

    try:
        with open(args.output, "wb") as f:
            f.write(line)
    except OSError as exc:
        print(f"cryptocore: ошибка: не удалось записать выходной файл: {exc}", file=sys.stderr)
        return 1
    return 0
