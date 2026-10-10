import argparse
from pathlib import Path

AES_128_KEY_LENGTH_BYTES = 16


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore — инструмент командной строки для операций с блочными шифрами.",
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="Алгоритм шифрования. В этом спринте поддерживается только 'aes'.",
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["ecb"],
        help="Режим работы. В этом спринте поддерживается только 'ecb'.",
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="Зашифровать входной файл.")
    operation.add_argument("--decrypt", action="store_true", help="Расшифровать входной файл.")

    parser.add_argument(
        "--key",
        required=True,
        help="Ключ в виде шестнадцатеричной строки (32 hex-символа / 16 байт для AES-128).",
    )
    parser.add_argument("--input", required=True, help="Путь к входному файлу.")
    parser.add_argument(
        "--output",
        required=False,
        default=None,
        help="Путь к выходному файлу (по умолчанию определяется на основе --input).",
    )

    return parser


def default_output_path(input_path: str, encrypt: bool) -> str:

    if encrypt:
        return f"{input_path}.enc"
    return f"{input_path}.dec"


def parse_and_validate(argv=None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError:
        parser.error("--key должен быть корректной шестнадцатеричной строкой")
        raise AssertionError("unreachable")  # parser.error() всегда завершает работу

    if len(key_bytes) != AES_128_KEY_LENGTH_BYTES:
        parser.error(
            "--key должен содержать "
            f"{AES_128_KEY_LENGTH_BYTES} байт ({AES_128_KEY_LENGTH_BYTES * 2} hex-символов) "
            f"для AES-128, получено {len(key_bytes)} байт"
        )

    if not Path(args.input).is_file():
        parser.error(f"входной файл не найден: {args.input}")

    if args.output is None:
        args.output = default_output_path(args.input, args.encrypt)

    args.key_bytes = key_bytes
    return args
