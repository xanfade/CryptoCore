import os
import shutil
import subprocess

import pytest

from tests.helpers import KEY, run_cryptocore

OPENSSL = shutil.which("openssl")
MODES = ["cbc", "cfb", "ofb", "ctr"]
LENGTHS = [0, 1, 16, 37, 1000]

pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl не найден в PATH")


def openssl(*args, cwd):
    result = subprocess.run([OPENSSL, "enc", *args], capture_output=True, cwd=cwd)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("length", LENGTHS)
def test_our_tool_to_openssl(mode, length, tmp_path):
    plain = os.urandom(length)
    (tmp_path / "plain.bin").write_bytes(plain)

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt", "--key", KEY,
        "--input", "plain.bin", "--output", "cipher.bin", cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr

    blob = (tmp_path / "cipher.bin").read_bytes()
    (tmp_path / "iv.bin").write_bytes(blob[:16])
    (tmp_path / "cipher_only.bin").write_bytes(blob[16:])

    openssl(
        f"-aes-128-{mode}", "-d", "-K", KEY, "-iv", blob[:16].hex(),
        "-in", "cipher_only.bin", "-out", "decrypted.bin", cwd=tmp_path,
    )
    assert (tmp_path / "decrypted.bin").read_bytes() == plain


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("length", LENGTHS)
def test_openssl_to_our_tool(mode, length, tmp_path):
    plain = os.urandom(length)
    iv = os.urandom(16).hex()
    (tmp_path / "plain.bin").write_bytes(plain)

    openssl(
        f"-aes-128-{mode}", "-K", KEY, "-iv", iv,
        "-in", "plain.bin", "-out", "openssl_cipher.bin", cwd=tmp_path,
    )

    result = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt", "--key", KEY, "--iv", iv,
        "--input", "openssl_cipher.bin", "--output", "decrypted.bin", cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "decrypted.bin").read_bytes() == plain
