import os
import re

import pytest
from Crypto.Cipher import AES

from cryptocore import __main__ as cli
from cryptocore import cli_parser
from cryptocore.csprng import CSPRNGError
from tests.helpers import run_cryptocore

KEY = "00112233445566778899aabbccddeeff"
AAD = "aabbccddeeff"
AUTH_ERROR = "[ERROR] Authentication failed: AAD mismatch or ciphertext tampered"
KEY_LINE = re.compile(r"^\[INFO\] Generated random key: ([0-9a-f]{32})$", re.MULTILINE)


def encrypt(tmp_path, data=b"Secret plaintext", aad=AAD, key=KEY, name="plaintext.txt", out="ciphertext.bin", extra=()):
    (tmp_path / name).write_bytes(data)
    args = ["--algorithm", "aes", "--mode", "gcm", "--encrypt", "--input", str(tmp_path / name),
            "--output", str(tmp_path / out), *extra]
    if key is not None:
        args += ["--key", key]
    if aad is not None:
        args += ["--aad", aad]
    return run_cryptocore(*args)


def decrypt(tmp_path, aad=AAD, key=KEY, name="ciphertext.bin", out="decrypted.txt", extra=()):
    args = ["--algorithm", "aes", "--mode", "gcm", "--decrypt", "--key", key, "--input", str(tmp_path / name),
            "--output", str(tmp_path / out), *extra]
    if aad is not None:
        args += ["--aad", aad]
    return run_cryptocore(*args)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100, 4096])
@pytest.mark.parametrize("aad", [AAD, None, "", "00"])
def test_roundtrip(size, aad, tmp_path):
    data = os.urandom(size)
    assert encrypt(tmp_path, data, aad=aad).returncode == 0
    result = decrypt(tmp_path, aad=aad)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "decrypted.txt").read_bytes() == data


def test_spec_example_flow(tmp_path):
    enc = encrypt(tmp_path)
    assert enc.returncode == 0 and enc.stdout == ""

    ok = decrypt(tmp_path)
    assert ok.returncode == 0
    assert ok.stdout.strip() == "[SUCCESS] Decryption completed successfully"
    assert (tmp_path / "decrypted.txt").read_bytes() == b"Secret plaintext"


def test_output_format_nonce_ciphertext_tag(tmp_path):
    encrypt(tmp_path, b"x" * 37)
    blob = (tmp_path / "ciphertext.bin").read_bytes()
    assert len(blob) == 12 + 37 + 16

    key = bytes.fromhex(KEY)
    reference = AES.new(key, AES.MODE_GCM, nonce=blob[:12])
    reference.update(bytes.fromhex(AAD))
    assert reference.decrypt_and_verify(blob[12:-16], blob[-16:]) == b"x" * 37


def test_each_run_uses_a_new_random_nonce(tmp_path):
    nonces = set()
    for i in range(5):
        encrypt(tmp_path, b"same", out=f"c{i}.bin")
        nonces.add((tmp_path / f"c{i}.bin").read_bytes()[:12])
    assert len(nonces) == 5


def test_wrong_aad_fails_catastrophically(tmp_path):
    encrypt(tmp_path)
    result = decrypt(tmp_path, aad="aabbccddee00")
    assert result.returncode == 1
    assert AUTH_ERROR in result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "decrypted.txt").exists()


@pytest.mark.parametrize("aad", [None, "", "aabbccddeeff00", "aabbccddee"])
def test_missing_or_different_aad_fails(aad, tmp_path):
    encrypt(tmp_path)
    result = decrypt(tmp_path, aad=aad)
    assert result.returncode == 1
    assert not (tmp_path / "decrypted.txt").exists()


def test_failed_authentication_leaves_existing_output_untouched(tmp_path):
    encrypt(tmp_path)
    (tmp_path / "decrypted.txt").write_bytes(b"previous content")
    assert decrypt(tmp_path, aad="00").returncode == 1
    assert (tmp_path / "decrypted.txt").read_bytes() == b"previous content"


def test_wrong_key_fails(tmp_path):
    encrypt(tmp_path)
    result = decrypt(tmp_path, key="ffeeddccbbaa99887766554433221100")
    assert result.returncode == 1 and AUTH_ERROR in result.stderr
    assert not (tmp_path / "decrypted.txt").exists()


@pytest.mark.parametrize("position", ["nonce_first", "nonce_last", "ct_first", "ct_middle", "ct_last", "tag_first", "tag_last"])
def test_tampering_anywhere_fails_without_output(position, tmp_path):
    encrypt(tmp_path, b"A message long enough to have several bytes")
    blob = bytearray((tmp_path / "ciphertext.bin").read_bytes())
    index = {
        "nonce_first": 0, "nonce_last": 11, "ct_first": 12, "ct_middle": 12 + (len(blob) - 28) // 2,
        "ct_last": len(blob) - 17, "tag_first": len(blob) - 16, "tag_last": len(blob) - 1,
    }[position]
    blob[index] ^= 0x01
    (tmp_path / "tampered.bin").write_bytes(bytes(blob))

    result = decrypt(tmp_path, name="tampered.bin", out="should_fail.txt")

    assert result.returncode == 1
    assert "[ERROR] Authentication failed" in result.stderr
    assert not (tmp_path / "should_fail.txt").exists()


@pytest.mark.parametrize("length", [0, 5, 27])
def test_input_shorter_than_nonce_and_tag_is_an_error(length, tmp_path):
    (tmp_path / "short.bin").write_bytes(bytes(length))
    result = decrypt(tmp_path, name="short.bin", out="out.txt")
    assert result.returncode == 1
    assert "слишком короткий" in result.stderr
    assert not (tmp_path / "out.txt").exists()


def test_explicit_nonce_on_encryption_is_deterministic_and_warns(tmp_path):
    zero_key = "00000000000000000000000000000000"
    first = encrypt(tmp_path, b"Hello GCM world", aad="", key=zero_key, out="a.bin", extra=["--iv", "00" * 12])
    second = encrypt(tmp_path, b"Hello GCM world", aad="", key=zero_key, out="b.bin", extra=["--nonce", "00" * 12])

    assert first.returncode == 0 and second.returncode == 0
    assert "nonce задан вручную" in first.stderr
    blob = (tmp_path / "a.bin").read_bytes()
    assert blob == (tmp_path / "b.bin").read_bytes()
    assert blob[:12] == bytes(12)

    reference = AES.new(bytes(16), AES.MODE_GCM, nonce=bytes(12))
    ciphertext, tag = reference.encrypt_and_digest(b"Hello GCM world")
    assert blob[12:] == ciphertext + tag


@pytest.mark.parametrize("flag", ["--iv", "--nonce"])
def test_decrypt_with_explicit_nonce_when_file_has_no_nonce(flag, tmp_path):
    encrypt(tmp_path, b"payload")
    blob = (tmp_path / "ciphertext.bin").read_bytes()
    (tmp_path / "no_nonce.bin").write_bytes(blob[12:])

    result = decrypt(tmp_path, name="no_nonce.bin", extra=[flag, blob[:12].hex()])

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "decrypted.txt").read_bytes() == b"payload"


def test_decrypt_with_wrong_explicit_nonce_fails(tmp_path):
    encrypt(tmp_path, b"payload")
    blob = (tmp_path / "ciphertext.bin").read_bytes()
    (tmp_path / "no_nonce.bin").write_bytes(blob[12:])
    result = decrypt(tmp_path, name="no_nonce.bin", extra=["--nonce", "00" * 12])
    assert result.returncode == 1 and AUTH_ERROR in result.stderr


def test_explicit_nonce_with_too_short_file_is_an_error(tmp_path):
    (tmp_path / "short.bin").write_bytes(bytes(10))
    result = decrypt(tmp_path, name="short.bin", extra=["--nonce", "00" * 12])
    assert result.returncode == 1 and "слишком короткий" in result.stderr


def test_invalid_aad_hex_is_rejected(tmp_path):
    encrypt(tmp_path)
    result = decrypt(tmp_path, aad="wrongaad123")
    assert result.returncode == 2
    assert "--aad" in result.stderr
    assert not (tmp_path / "decrypted.txt").exists()


@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb", "ctr"])
def test_aad_is_rejected_for_modes_without_authentication(mode, tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    result = run_cryptocore("--algorithm", "aes", "--mode", mode, "--encrypt", "--key", KEY,
                            "--aad", AAD, "--input", str(tmp_path / "f"), "--output", str(tmp_path / "o"))
    assert result.returncode == 2
    assert "gcm" in result.stderr


@pytest.mark.parametrize("bad_nonce", ["00" * 11, "00" * 16, "zz"])
def test_nonce_must_be_12_bytes_hex_for_gcm(bad_nonce, tmp_path):
    result = encrypt(tmp_path, extra=["--iv", bad_nonce])
    assert result.returncode == 2


def test_other_modes_still_reject_iv_on_encryption(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    result = run_cryptocore("--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", KEY,
                            "--iv", "00" * 16, "--input", str(tmp_path / "f"), "--output", str(tmp_path / "o"))
    assert result.returncode == 2


def test_other_modes_print_nothing_on_successful_decryption(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    run_cryptocore("--algorithm", "aes", "--mode", "ctr", "--encrypt", "--key", KEY,
                   "--input", str(tmp_path / "f"), "--output", str(tmp_path / "c"))
    result = run_cryptocore("--algorithm", "aes", "--mode", "ctr", "--decrypt", "--key", KEY,
                            "--input", str(tmp_path / "c"), "--output", str(tmp_path / "d"))
    assert result.returncode == 0 and result.stdout == ""


def test_generated_key_works_with_gcm_and_aad(tmp_path):
    result = encrypt(tmp_path, key=None)
    assert result.returncode == 0
    key = KEY_LINE.search(result.stdout).group(1)
    assert decrypt(tmp_path, key=key).returncode == 0
    assert (tmp_path / "decrypted.txt").read_bytes() == b"Secret plaintext"


def test_key_and_nonce_come_from_csprng_function(monkeypatch, tmp_path, capsys):
    calls = []

    def fake_random(num_bytes):
        calls.append(num_bytes)
        return bytes([0x7E]) * num_bytes

    monkeypatch.setattr(cli, "generate_random_bytes", fake_random)
    (tmp_path / "in.bin").write_bytes(b"hello")
    code = cli.main(["--algorithm", "aes", "--mode", "gcm", "--encrypt", "--aad", AAD,
                     "--input", str(tmp_path / "in.bin"), "--output", str(tmp_path / "out.bin")])

    assert code == 0
    assert calls == [16, 12]
    assert (tmp_path / "out.bin").read_bytes()[:12] == bytes([0x7E]) * 12
    assert "7e" * 16 in capsys.readouterr().out


def test_csprng_failure_gives_clear_error_and_no_output(monkeypatch, tmp_path, capsys):
    def broken(num_bytes):
        raise CSPRNGError("источник случайности недоступен")

    monkeypatch.setattr(cli, "generate_random_bytes", broken)
    (tmp_path / "in.bin").write_bytes(b"hello")
    code = cli.main(["--algorithm", "aes", "--mode", "gcm", "--encrypt", "--key", KEY,
                     "--input", str(tmp_path / "in.bin"), "--output", str(tmp_path / "out.bin")])
    assert code == 1
    assert "источник случайности недоступен" in capsys.readouterr().err
    assert not (tmp_path / "out.bin").exists()


def test_interoperability_with_openssl_backed_library(tmp_path):
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key = bytes.fromhex(KEY)
    aad = bytes.fromhex(AAD)

    encrypt(tmp_path, b"from cryptocore to openssl")
    blob = (tmp_path / "ciphertext.bin").read_bytes()
    assert aead.AESGCM(key).decrypt(blob[:12], blob[12:], aad) == b"from cryptocore to openssl"

    nonce = os.urandom(12)
    (tmp_path / "from_openssl.bin").write_bytes(nonce + aead.AESGCM(key).encrypt(nonce, b"from openssl", aad))
    result = decrypt(tmp_path, name="from_openssl.bin", out="d2.txt")
    assert result.returncode == 0
    assert (tmp_path / "d2.txt").read_bytes() == b"from openssl"


# ---- разбор аргументов ----

def parse(tmp_path, *extra):
    (tmp_path / "f").write_bytes(b"x")
    return cli_parser.parse_and_validate(
        ["--algorithm", "aes", "--mode", "gcm", "--key", KEY, "--input", str(tmp_path / "f"), *extra]
    )


def test_parser_accepts_gcm_and_defaults_to_empty_aad(tmp_path):
    args = parse(tmp_path, "--encrypt")
    assert args.mode == "gcm" and args.aad_bytes == b"" and args.iv_bytes is None


def test_parser_reads_aad_and_nonce_alias(tmp_path):
    args = parse(tmp_path, "--decrypt", "--aad", "00ff", "--nonce", "01" * 12)
    assert args.aad_bytes == b"\x00\xff"
    assert args.iv_bytes == b"\x01" * 12


def test_parser_allows_nonce_on_gcm_encryption(tmp_path):
    assert parse(tmp_path, "--encrypt", "--iv", "02" * 12).iv_bytes == b"\x02" * 12
