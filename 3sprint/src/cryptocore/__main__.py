import os
import sys

from cryptocore.cli_parser import parse_and_validate
from cryptocore.file_io import read_file, write_file
from cryptocore.modes import cbc, cfb, ctr, ecb, ofb
from cryptocore.modes.common import BLOCK_SIZE

IV_MODES = {"cbc": cbc, "cfb": cfb, "ofb": ofb, "ctr": ctr}


def fail(message: str) -> int:
    print(f"cryptocore: ошибка: {message}", file=sys.stderr)
    return 1


def run(args, data: bytes) -> bytes:
    if args.mode == "ecb":
        if args.encrypt:
            return ecb.encrypt(args.key_bytes, data)
        return ecb.decrypt(args.key_bytes, data)

    mode = IV_MODES[args.mode]
    if args.encrypt:
        iv = os.urandom(BLOCK_SIZE)
        return iv + mode.encrypt(args.key_bytes, data, iv)

    if args.iv_bytes is not None:
        iv = args.iv_bytes
    else:
        if len(data) < BLOCK_SIZE:
            raise ValueError(
                f"входной файл слишком короткий: для получения IV нужно минимум {BLOCK_SIZE} байт, "
                f"найдено {len(data)}"
            )
        iv, data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return mode.decrypt(args.key_bytes, data, iv)


def main(argv=None) -> int:
    args = parse_and_validate(argv)

    try:
        data = read_file(args.input)
    except OSError as exc:
        return fail(f"не удалось прочитать входной файл: {exc}")

    try:
        result = run(args, data)
    except ValueError as exc:
        return fail(str(exc))

    try:
        write_file(args.output, result)
    except OSError as exc:
        return fail(f"не удалось записать выходной файл: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
