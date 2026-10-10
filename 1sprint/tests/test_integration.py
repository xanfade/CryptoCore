import subprocess
import sys

KEY = "000102030405060708090a0b0c0d0e0f"


def run_cryptocore(*args):
    result = subprocess.run(
        [sys.executable, "-m", "cryptocore", *args],
        capture_output=True,
        text=True,
    )
    return result


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
