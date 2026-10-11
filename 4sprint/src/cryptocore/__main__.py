import sys

from cryptocore.cli_parser import AES_128_KEY_LENGTH_BYTES, parse_and_validate
from cryptocore.csprng import CSPRNGError, generate_random_bytes
from cryptocore.dgst import run_dgst
from cryptocore.file_io import read_file, write_file
from cryptocore.key_checks import weak_key_reason
from cryptocore.modes import cbc, cfb, ctr, ecb, ofb
from cryptocore.modes.common import BLOCK_SIZE

IV_MODES = {"cbc": cbc, "cfb": cfb, "ofb": ofb, "ctr": ctr}


def fail(message: str) -> int:
    print(f"cryptocore: ошибка: {message}", file=sys.stderr)
    return 1


def prepare_key(args) -> None:
    if args.key_bytes is None:
        args.key_bytes = generate_random_bytes(AES_128_KEY_LENGTH_BYTES)
        print(f"[INFO] Generated random key: {args.key_bytes.hex()}", flush=True)
        return

    reason = weak_key_reason(args.key_bytes)
    if reason is not None:
        print(
            f"cryptocore: предупреждение: слабый ключ ({reason}). "
            "Используйте случайный ключ: просто не указывайте --key при шифровании",
            file=sys.stderr,
        )


def run(args, data: bytes) -> bytes:
    if args.mode == "ecb":
        if args.encrypt:
            return ecb.encrypt(args.key_bytes, data)
        return ecb.decrypt(args.key_bytes, data)

    mode = IV_MODES[args.mode]
    if args.encrypt:
        iv = generate_random_bytes(BLOCK_SIZE)
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
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "dgst":
        return run_dgst(argv[1:])

    args = parse_and_validate(argv)

    try:
        data = read_file(args.input)
    except OSError as exc:
        return fail(f"не удалось прочитать входной файл: {exc}")

    try:
        prepare_key(args)
        result = run(args, data)
    except (ValueError, CSPRNGError) as exc:
        return fail(str(exc))

    try:
        write_file(args.output, result)
    except OSError as exc:
        return fail(f"не удалось записать выходной файл: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
