from tests.helpers import KEY, run_cryptocore


def test_encrypt_then_decrypt_reproduces_original_text_file(tmp_path):
    original = tmp_path / "original_file.txt"
    original.write_text("The primary acceptance test must pass.\n")

    ciphertext = tmp_path / "ciphertext.bin"
    decrypted = tmp_path / "decrypted_file.txt"

    encrypt_result = run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    )
    assert encrypt_result.returncode == 0, encrypt_result.stderr

    decrypt_result = run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--decrypt",
        "--key", KEY, "--input", str(ciphertext), "--output", str(decrypted),
    )
    assert decrypt_result.returncode == 0, decrypt_result.stderr

    assert decrypted.read_bytes() == original.read_bytes()


def test_encrypt_then_decrypt_reproduces_original_binary_file(tmp_path):
    original = tmp_path / "original_file.bin"
    original.write_bytes(bytes(range(256)) * 4)

    ciphertext = tmp_path / "ciphertext.bin"
    decrypted = tmp_path / "decrypted_file.bin"

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    ).returncode == 0

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--decrypt",
        "--key", KEY, "--input", str(ciphertext), "--output", str(decrypted),
    ).returncode == 0

    assert decrypted.read_bytes() == original.read_bytes()


def test_default_output_filenames_are_derived_from_input(tmp_path):
    original = tmp_path / "plaintext.txt"
    original.write_text("default filename check")

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--encrypt",
        "--key", KEY, "--input", str(original),
    ).returncode == 0

    ciphertext = tmp_path / "plaintext.txt.enc"
    assert ciphertext.exists()

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--decrypt",
        "--key", KEY, "--input", str(ciphertext),
    ).returncode == 0

    decrypted = tmp_path / "plaintext.txt.enc.dec"
    assert decrypted.exists()
    assert decrypted.read_bytes() == original.read_bytes()


import os

import pytest

IV_MODES = ["cbc", "cfb", "ofb", "ctr"]


@pytest.mark.parametrize("mode", IV_MODES)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 100, 1024])
def test_roundtrip_iv_modes(mode, length, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(os.urandom(length))
    ciphertext = tmp_path / "cipher.bin"
    decrypted = tmp_path / "decrypted.bin"

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    ).returncode == 0

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt",
        "--key", KEY, "--input", str(ciphertext), "--output", str(decrypted),
    )
    assert result.returncode == 0, result.stderr
    assert decrypted.read_bytes() == original.read_bytes()


@pytest.mark.parametrize("mode,expected_size", [("cbc", 16 + 32), ("cfb", 16 + 20), ("ofb", 16 + 20), ("ctr", 16 + 20)])
def test_iv_is_prepended_to_output(mode, expected_size, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes(20))
    ciphertext = tmp_path / "cipher.bin"

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    ).returncode == 0
    assert len(ciphertext.read_bytes()) == expected_size


@pytest.mark.parametrize("mode", IV_MODES)
def test_each_encryption_uses_new_random_iv(mode, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"same data")
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    for out in (first, second):
        assert run_cryptocore(
            "--algorithm", "aes", "--mode", mode, "--encrypt",
            "--key", KEY, "--input", str(original), "--output", str(out),
        ).returncode == 0

    assert first.read_bytes()[:16] != second.read_bytes()[:16]


@pytest.mark.parametrize("mode", IV_MODES)
def test_decrypt_with_explicit_iv(mode, tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(os.urandom(50))
    ciphertext = tmp_path / "cipher.bin"
    body = tmp_path / "body.bin"
    decrypted = tmp_path / "decrypted.bin"

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    ).returncode == 0

    blob = ciphertext.read_bytes()
    body.write_bytes(blob[16:])

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt", "--key", KEY,
        "--iv", blob[:16].hex(), "--input", str(body), "--output", str(decrypted),
    )
    assert result.returncode == 0, result.stderr
    assert decrypted.read_bytes() == original.read_bytes()


@pytest.mark.parametrize("mode", IV_MODES)
def test_decrypt_file_shorter_than_iv_fails(mode, tmp_path):
    short = tmp_path / "short.bin"
    short.write_bytes(bytes(10))

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt", "--key", KEY,
        "--input", str(short), "--output", str(tmp_path / "out.bin"),
    )
    assert result.returncode != 0
    assert "слишком короткий" in result.stderr
    assert not (tmp_path / "out.bin").exists()


def test_iv_flag_rejected_on_encryption(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"data")

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", KEY,
        "--iv", "00" * 16, "--input", str(original), "--output", str(tmp_path / "out.bin"),
    )
    assert result.returncode != 0
    assert "--iv" in result.stderr


def test_ecb_format_has_no_iv(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes(16))
    ciphertext = tmp_path / "cipher.bin"

    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "ecb", "--encrypt",
        "--key", KEY, "--input", str(original), "--output", str(ciphertext),
    ).returncode == 0
    assert len(ciphertext.read_bytes()) == 32
