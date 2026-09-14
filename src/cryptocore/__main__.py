import sys

from cryptocore.cli_parser import parse_and_validate
from cryptocore.file_io import read_file, write_file
from cryptocore.modes import ecb


def main(argv=None) -> int:
    args = parse_and_validate(argv)

    try:
        data = read_file(args.input)
    except OSError as exc:
        print(f"cryptocore: ошибка: не удалось прочитать входной файл: {exc}", file=sys.stderr)
        return 1

    try:
        if args.encrypt:
            result = ecb.encrypt(args.key_bytes, data)
        else:
            result = ecb.decrypt(args.key_bytes, data)
    except ValueError as exc:
        print(f"cryptocore: ошибка: {exc}", file=sys.stderr)
        return 1

    try:
        write_file(args.output, result)
    except OSError as exc:
        print(f"cryptocore: ошибка: не удалось записать выходной файл: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
