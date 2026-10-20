import os
import re

import pytest

from cryptocore import __main__ as cli
from cryptocore.csprng import CSPRNGError
from tests.helpers import KEY, run_cryptocore

MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]
KEY_LINE = re.compile(r"^\[INFO\] Generated random key: ([0-9a-f]{32})$", re.MULTILINE)


def encrypt_without_key(mode, original, ciphertext):
    return run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt",
        "--input", str(original), "--output", str(ciphertext),
    )


@pytest.mark.parametrize("mode", MODES)
def test_encrypt_without_key_prints_key_and_roundtrips(mode, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(os.urandom(77))
    ciphertext = tmp_path / "cipher.bin"
    decrypted = tmp_path / "decrypted.bin"

    result = encrypt_without_key(mode, original, ciphertext)
    assert result.returncode == 0, result.stderr

    matches = KEY_LINE.findall(result.stdout)
    assert len(matches) == 1
    assert result.stdout.count("Generated random key") == 1
    key_hex = matches[0]

    decrypt_result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt", "--key", key_hex,
        "--input", str(ciphertext), "--output", str(decrypted),
    )
    assert decrypt_result.returncode == 0, decrypt_result.stderr
    assert decrypted.read_bytes() == original.read_bytes()


@pytest.mark.parametrize("mode", MODES)
def test_generated_key_is_not_written_to_ciphertext(mode, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes(48))
    ciphertext = tmp_path / "cipher.bin"

    result = encrypt_without_key(mode, original, ciphertext)
    key = bytes.fromhex(KEY_LINE.search(result.stdout).group(1))
    assert key not in ciphertext.read_bytes()


def test_each_run_generates_a_different_key(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"data")
    keys = set()
    for i in range(5):
        result = encrypt_without_key("cbc", original, tmp_path / f"c{i}.bin")
        keys.add(KEY_LINE.search(result.stdout).group(1))
    assert len(keys) == 5


def test_stdout_is_empty_when_key_is_provided(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"data")

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", "1a2b3c4d5e6f7890fedcba9876543210",
        "--input", str(original), "--output", str(tmp_path / "c.bin"),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_decrypt_without_key_fails(tmp_path):
    cipher = tmp_path / "cipher.bin"
    cipher.write_bytes(bytes(32))

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", "cbc", "--decrypt",
        "--input", str(cipher), "--output", str(tmp_path / "out.bin"),
    )
    assert result.returncode != 0
    assert "--key" in result.stderr
    assert not (tmp_path / "out.bin").exists()


@pytest.mark.parametrize("weak", ["00" * 16, "41" * 16, KEY, "0f0e0d0c0b0a09080706050403020100"])
def test_weak_key_prints_warning_to_stderr(weak, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"data")

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", "ctr", "--encrypt", "--key", weak,
        "--input", str(original), "--output", str(tmp_path / "c.bin"),
    )
    assert result.returncode == 0, result.stderr
    assert "предупреждение" in result.stderr
    assert "слаб" in result.stderr
    assert result.stdout == ""


def test_generated_key_does_not_trigger_warning(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"data")

    result = encrypt_without_key("ctr", original, tmp_path / "c.bin")
    assert result.stderr == ""


def test_generated_key_is_16_bytes_from_csprng(monkeypatch, tmp_path, capsys):
    calls = []

    def fake_random(num_bytes):
        calls.append(num_bytes)
        return bytes([0xAB]) * num_bytes

    monkeypatch.setattr(cli, "generate_random_bytes", fake_random)
    original = tmp_path / "original.bin"
    original.write_bytes(b"hello")
    ciphertext = tmp_path / "cipher.bin"

    code = cli.main([
        "--algorithm", "aes", "--mode", "cbc", "--encrypt",
        "--input", str(original), "--output", str(ciphertext),
    ])

    assert code == 0
    assert calls == [16, 16]
    assert "[INFO] Generated random key: " + "ab" * 16 in capsys.readouterr().out
    assert ciphertext.read_bytes()[:16] == bytes([0xAB]) * 16


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_iv_comes_from_csprng_function(monkeypatch, mode, tmp_path):
    monkeypatch.setattr(cli, "generate_random_bytes", lambda n: bytes([0x5C]) * n)
    original = tmp_path / "original.bin"
    original.write_bytes(b"hello")
    ciphertext = tmp_path / "cipher.bin"

    code = cli.main([
        "--algorithm", "aes", "--mode", mode, "--encrypt", "--key", "1a2b3c4d5e6f7890fedcba9876543210",
        "--input", str(original), "--output", str(ciphertext),
    ])

    assert code == 0
    assert ciphertext.read_bytes()[:16] == bytes([0x5C]) * 16


def test_csprng_failure_gives_clear_error_and_no_output(monkeypatch, tmp_path, capsys):
    def broken(num_bytes):
        raise CSPRNGError("источник случайности недоступен")

    monkeypatch.setattr(cli, "generate_random_bytes", broken)
    original = tmp_path / "original.bin"
    original.write_bytes(b"hello")
    ciphertext = tmp_path / "cipher.bin"

    code = cli.main([
        "--algorithm", "aes", "--mode", "cbc", "--encrypt",
        "--input", str(original), "--output", str(ciphertext),
    ])

    captured = capsys.readouterr()
    assert code == 1
    assert "источник случайности недоступен" in captured.err
    assert "Generated random key" not in captured.out
    assert not ciphertext.exists()
