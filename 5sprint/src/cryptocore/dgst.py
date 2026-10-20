import argparse
import secrets
import sys
from pathlib import Path

from cryptocore.hash import ALGORITHMS
from cryptocore.mac.cmac import KEY_LENGTH as CMAC_KEY_LENGTH
from cryptocore.mac.cmac import AESCMAC
from cryptocore.mac.hmac import HMAC

CHUNK_SIZE = 8192
STDIN_NAME = "-"
CMAC_ALGORITHM = "aes"
MAX_EXPECTED_MAC_FILE_SIZE = 1_000_000
HEX_DIGITS = set("0123456789abcdef")


def build_dgst_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Вычисляет хеш или код аутентификации (HMAC, AES-CMAC) файла. "
                    "Формат вывода как у sha256sum: ЗНАЧЕНИЕ  ФАЙЛ.",
    )
    parser.add_argument(
        "--algorithm",
        required=False,
        choices=sorted(ALGORITHMS) + [CMAC_ALGORITHM],
        help="Алгоритм хеширования: sha256 или sha3-256 (для --hmac — хеш-функция HMAC). "
             "С --cmac можно не указывать (всегда AES) или указать aes.",
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
    parser.add_argument("--hmac", action="store_true", help="Вычислить HMAC (RFC 2104); требует --key.")
    parser.add_argument("--cmac", action="store_true", help="Вычислить AES-CMAC (NIST SP 800-38B); требует --key (16 байт).")
    parser.add_argument(
        "--key",
        required=False,
        default=None,
        help="Ключ в hex произвольной длины для --hmac; ровно 16 байт (32 hex-символа) для --cmac.",
    )
    parser.add_argument(
        "--verify",
        required=False,
        default=None,
        metavar="FILE",
        help="Файл с ожидаемым значением MAC: вычисленное значение сравнивается с ним. "
             "Код возврата 0 при совпадении, 1 при несовпадении.",
    )
    return parser


def parse_dgst_args(argv):
    parser = build_dgst_parser()
    args = parser.parse_args(argv)

    if args.hmac and args.cmac:
        parser.error("--hmac и --cmac нельзя использовать вместе")

    args.key_bytes = None
    if args.hmac or args.cmac:
        flag = "--hmac" if args.hmac else "--cmac"
        if args.key is None:
            parser.error(f"--key обязателен при использовании {flag}")
        try:
            args.key_bytes = bytes.fromhex(args.key)
        except ValueError:
            parser.error("--key должен быть корректной шестнадцатеричной строкой")
        if args.cmac and len(args.key_bytes) != CMAC_KEY_LENGTH:
            parser.error(
                f"--key для --cmac должен содержать {CMAC_KEY_LENGTH} байт "
                f"({CMAC_KEY_LENGTH * 2} hex-символов), получено {len(args.key_bytes)} байт"
            )
    else:
        if args.key is not None:
            parser.error("--key допустим только вместе с --hmac или --cmac")
        if args.verify is not None:
            parser.error("--verify допустим только вместе с --hmac или --cmac")

    if args.cmac:
        if args.algorithm not in (None, CMAC_ALGORITHM):
            parser.error("с --cmac допустим только алгоритм aes (или без --algorithm)")
    else:
        if args.algorithm is None:
            parser.error("the following arguments are required: --algorithm")
        if args.algorithm == CMAC_ALGORITHM:
            parser.error("алгоритм aes доступен только вместе с --cmac")

    if args.verify is not None and args.output is not None:
        parser.error("--output нельзя использовать вместе с --verify")

    args.mac_name = "HMAC" if args.hmac else "CMAC" if args.cmac else None
    return parser, args


def feed_stream(stream, hasher) -> None:
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)


def hash_stream(stream, algorithm: str) -> str:
    hasher = ALGORITHMS[algorithm]()
    feed_stream(stream, hasher)
    return hasher.hexdigest()


def create_hasher(args):
    if args.hmac:
        return HMAC(args.key_bytes, args.algorithm)
    if args.cmac:
        return AESCMAC(args.key_bytes)
    return ALGORITHMS[args.algorithm]()


def read_expected_mac(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read(MAX_EXPECTED_MAC_FILE_SIZE + 1)
    if len(raw) > MAX_EXPECTED_MAC_FILE_SIZE:
        raise ValueError(f"файл с ожидаемым значением слишком большой: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"файл с ожидаемым значением не является текстом: {path}") from None

    tokens = text.split()
    if not tokens:
        raise ValueError(f"файл с ожидаемым значением пуст: {path}")

    expected = tokens[0].lower()
    if not set(expected) <= HEX_DIGITS:
        raise ValueError(f"в файле {path} первое слово не является шестнадцатеричным значением")
    return expected


def run_dgst(argv) -> int:
    parser, args = parse_dgst_args(argv)

    expected = None
    if args.verify is not None:
        try:
            expected = read_expected_mac(args.verify)
        except OSError as exc:
            print(f"[ERROR] не удалось прочитать файл с ожидаемым значением: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1

    try:
        hasher = create_hasher(args)
        if args.input == STDIN_NAME:
            feed_stream(sys.stdin.buffer, hasher)
        else:
            if not Path(args.input).is_file():
                parser.error(f"входной файл не найден: {args.input}")
            with open(args.input, "rb") as f:
                feed_stream(f, hasher)
        digest = hasher.hexdigest()
    except OSError as exc:
        print(f"cryptocore: ошибка: не удалось прочитать входной файл: {exc}", file=sys.stderr)
        return 1

    if expected is not None:
        if secrets.compare_digest(digest.encode("ascii"), expected.encode("ascii")):
            sys.stdout.buffer.write(f"[OK] {args.mac_name} verification successful\n".encode("utf-8"))
            sys.stdout.buffer.flush()
            return 0
        print(f"[ERROR] {args.mac_name} verification failed", file=sys.stderr)
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
