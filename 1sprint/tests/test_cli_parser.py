import pytest

from cryptocore import cli_parser

VALID_KEY = "000102030405060708090a0b0c0d0e0f"


@pytest.fixture
def input_file(tmp_path):
    path = tmp_path / "plaintext.txt"
    path.write_bytes(b"hello world")
    return str(path)


def test_valid_encrypt_args_parse(input_file):
    args = cli_parser.parse_and_validate(
        ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", VALID_KEY, "--input", input_file]
    )
    assert args.encrypt is True
    assert args.decrypt is False
    assert args.key_bytes == bytes.fromhex(VALID_KEY)
    assert args.output == f"{input_file}.enc"


def test_valid_decrypt_args_parse(input_file):
    args = cli_parser.parse_and_validate(
        ["--algorithm", "aes", "--mode", "ecb", "--decrypt", "--key", VALID_KEY, "--input", input_file]
    )
    assert args.decrypt is True
    assert args.output == f"{input_file}.dec"


def test_explicit_output_is_respected(input_file, tmp_path):
    out_path = str(tmp_path / "custom.out")
    args = cli_parser.parse_and_validate(
        [
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", VALID_KEY, "--input", input_file, "--output", out_path,
        ]
    )
    assert args.output == out_path


def test_missing_required_argument_exits_nonzero(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--mode", "ecb", "--encrypt", "--key", VALID_KEY, "--input", input_file]
        )
    assert exc_info.value.code != 0
    assert "algorithm" in capsys.readouterr().err.lower()


def test_both_encrypt_and_decrypt_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            [
                "--algorithm", "aes", "--mode", "ecb", "--encrypt", "--decrypt",
                "--key", VALID_KEY, "--input", input_file,
            ]
        )
    assert exc_info.value.code != 0
    assert "not allowed" in capsys.readouterr().err.lower()


def test_neither_encrypt_nor_decrypt_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "aes", "--mode", "ecb", "--key", VALID_KEY, "--input", input_file]
        )
    assert exc_info.value.code != 0


def test_non_hex_key_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", "not-hex", "--input", input_file]
        )
    assert exc_info.value.code != 0
    assert "шестнадцатеричн" in capsys.readouterr().err.lower()


def test_wrong_length_key_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", "aabb", "--input", input_file]
        )
    assert exc_info.value.code != 0
    assert "16 байт" in capsys.readouterr().err


def test_nonexistent_input_file_is_rejected(capsys, tmp_path):
    missing = str(tmp_path / "does-not-exist.txt")
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", VALID_KEY, "--input", missing]
        )
    assert exc_info.value.code != 0
    assert "не найден" in capsys.readouterr().err.lower()


def test_unsupported_algorithm_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "des", "--mode", "ecb", "--encrypt", "--key", VALID_KEY, "--input", input_file]
        )
    assert exc_info.value.code != 0


def test_unsupported_mode_is_rejected(capsys, input_file):
    with pytest.raises(SystemExit) as exc_info:
        cli_parser.parse_and_validate(
            ["--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", VALID_KEY, "--input", input_file]
        )
    assert exc_info.value.code != 0
