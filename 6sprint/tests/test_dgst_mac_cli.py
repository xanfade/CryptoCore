import hashlib
import hmac as std_hmac
import os
import shutil
import subprocess
import sys

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from tests.helpers import SRC_DIR

KEY = "00112233445566778899aabbccddeeff"
RFC_KEY = "0b" * 20
RFC_EXPECTED = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def dgst(*args, cwd=None, stdin=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-m", "cryptocore", "dgst", *args],
        input=stdin, capture_output=True, env=env, cwd=cwd,
    )
    result.out = result.stdout.decode("utf-8")
    result.err = result.stderr.decode("utf-8")
    return result


def hmac_args(key=KEY, name="file.txt"):
    return ["--algorithm", "sha256", "--hmac", "--key", key, "--input", name]


def test_rfc_4231_vector_1_through_cli(tmp_path):
    (tmp_path / "test_file.txt").write_bytes(b"Hi There")
    result = dgst(*hmac_args(RFC_KEY, "test_file.txt"), cwd=tmp_path)
    assert result.returncode == 0, result.err
    assert result.out == f"{RFC_EXPECTED}  test_file.txt\n"


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1000, 20000])
def test_output_matches_standard_library(size, tmp_path):
    data = os.urandom(size)
    (tmp_path / "file.txt").write_bytes(data)
    result = dgst(*hmac_args(), cwd=tmp_path)
    expected = std_hmac.new(bytes.fromhex(KEY), data, hashlib.sha256).hexdigest()
    assert result.out == f"{expected}  file.txt\n"


@pytest.mark.parametrize("key_bytes", [1, 16, 64, 100, 200])
def test_arbitrary_key_lengths(key_bytes, tmp_path):
    key = os.urandom(key_bytes)
    (tmp_path / "file.txt").write_bytes(b"message")
    result = dgst(*hmac_args(key.hex()), cwd=tmp_path)
    assert result.out.split()[0] == std_hmac.new(key, b"message", hashlib.sha256).hexdigest()


def test_hmac_with_sha3_256(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"message")
    result = dgst("--algorithm", "sha3-256", "--hmac", "--key", KEY, "--input", "file.txt", cwd=tmp_path)
    expected = std_hmac.new(bytes.fromhex(KEY), b"message", hashlib.sha3_256).hexdigest()
    assert result.out.split()[0] == expected


def test_empty_file(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"")
    result = dgst(*hmac_args(), cwd=tmp_path)
    assert result.out.split()[0] == std_hmac.new(bytes.fromhex(KEY), b"", hashlib.sha256).hexdigest()


def test_stdin_input():
    result = dgst("--algorithm", "sha256", "--hmac", "--key", RFC_KEY, "--input", "-", stdin=b"Hi There")
    assert result.out == f"{RFC_EXPECTED}  -\n"


def test_output_flag_writes_standard_format(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"data")
    to_stdout = dgst(*hmac_args(), cwd=tmp_path)
    to_file = dgst(*hmac_args(), "--output", "mac.txt", cwd=tmp_path)
    assert to_file.returncode == 0 and to_file.out == ""
    assert (tmp_path / "mac.txt").read_bytes() == to_stdout.stdout


def test_verify_succeeds_for_generated_hmac(tmp_path):
    (tmp_path / "message.txt").write_bytes(b"important message")
    dgst(*hmac_args(name="message.txt"), "--output", "expected_hmac.txt", cwd=tmp_path)

    result = dgst(*hmac_args(name="message.txt"), "--verify", "expected_hmac.txt", cwd=tmp_path)

    assert result.returncode == 0, result.err
    assert result.out == "[OK] HMAC verification successful\n"


def test_verify_detects_modified_file(tmp_path):
    target = tmp_path / "file.txt"
    target.write_bytes(b"original content\n")
    dgst(*hmac_args(), "--output", "original_hmac.txt", cwd=tmp_path)

    modified = bytearray(target.read_bytes())
    modified[0] ^= 0x01
    target.write_bytes(bytes(modified))

    result = dgst(*hmac_args(), "--verify", "original_hmac.txt", cwd=tmp_path)
    assert result.returncode == 1
    assert "[ERROR] HMAC verification failed" in result.err
    assert result.out == ""


def test_verify_detects_wrong_key(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"content")
    dgst(*hmac_args(), "--output", "original_hmac.txt", cwd=tmp_path)

    other_key = "ffeeddccbbaa99887766554433221100"
    result = dgst(*hmac_args(other_key), "--verify", "original_hmac.txt", cwd=tmp_path)

    assert result.returncode == 1
    assert "[ERROR] HMAC verification failed" in result.err


@pytest.mark.parametrize("make_content", [
    lambda mac: mac,
    lambda mac: mac + "\n",
    lambda mac: mac.upper(),
    lambda mac: f"  {mac}  file.txt  \r\n",
    lambda mac: f"{mac}  другое_имя.txt\n\n",
    lambda mac: f"\n\t{mac}\tfile.txt\n",
])
def test_verify_parses_expected_file_flexibly(make_content, tmp_path):
    (tmp_path / "file.txt").write_bytes(b"flexible parsing")
    mac = dgst(*hmac_args(), cwd=tmp_path).out.split()[0]
    (tmp_path / "expected.txt").write_bytes(make_content(mac).encode("utf-8"))

    result = dgst(*hmac_args(), "--verify", "expected.txt", cwd=tmp_path)
    assert result.returncode == 0, result.err


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"])
def test_verify_accepts_files_with_bom_and_utf16(encoding, tmp_path):
    # Windows PowerShell 5.1 при перенаправлении `>` создаёт файл UTF-16 с BOM
    (tmp_path / "file.txt").write_bytes(b"powershell")
    mac_line = dgst(*hmac_args(), cwd=tmp_path).out
    data = mac_line.replace("\n", "\r\n").encode(encoding)
    if encoding in ("utf-16-le", "utf-16-be"):
        data = (b"\xff\xfe" if encoding == "utf-16-le" else b"\xfe\xff") + data
    (tmp_path / "expected.txt").write_bytes(data)

    result = dgst(*hmac_args(), "--verify", "expected.txt", cwd=tmp_path)
    assert result.returncode == 0, result.err


@pytest.mark.parametrize("content", [b"", b"   \n", b"not hex at all\n", b"\xff\xfe\x00"])
def test_verify_with_malformed_expected_file_fails(content, tmp_path):
    (tmp_path / "file.txt").write_bytes(b"data")
    (tmp_path / "expected.txt").write_bytes(content)
    result = dgst(*hmac_args(), "--verify", "expected.txt", cwd=tmp_path)
    assert result.returncode != 0
    assert "[ERROR]" in result.err


def test_verify_with_truncated_value_fails(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"data")
    mac = dgst(*hmac_args(), cwd=tmp_path).out.split()[0]
    (tmp_path / "expected.txt").write_text(mac[:-2])
    assert dgst(*hmac_args(), "--verify", "expected.txt", cwd=tmp_path).returncode == 1


def test_verify_with_missing_expected_file_fails(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"data")
    result = dgst(*hmac_args(), "--verify", "nope.txt", cwd=tmp_path)
    assert result.returncode != 0
    assert "[ERROR]" in result.err


def test_verify_from_stdin(tmp_path):
    (tmp_path / "expected.txt").write_text(f"{RFC_EXPECTED}  -\n")
    result = dgst("--algorithm", "sha256", "--hmac", "--key", RFC_KEY, "--input", "-",
                  "--verify", "expected.txt", cwd=tmp_path, stdin=b"Hi There")
    assert result.returncode == 0, result.err


def test_hmac_requires_key(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"x")
    result = dgst("--algorithm", "sha256", "--hmac", "--input", "file.txt", cwd=tmp_path)
    assert result.returncode != 0
    assert "--key" in result.err


@pytest.mark.parametrize("bad_key", ["zz", "abc", "0g"])
def test_hmac_key_must_be_hex(bad_key, tmp_path):
    (tmp_path / "file.txt").write_bytes(b"x")
    result = dgst(*hmac_args(bad_key), cwd=tmp_path)
    assert result.returncode != 0
    assert "шестнадцатеричн" in result.err


def test_verify_requires_hmac_or_cmac(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"x")
    (tmp_path / "e.txt").write_text("00")
    result = dgst("--algorithm", "sha256", "--input", "file.txt", "--verify", "e.txt", cwd=tmp_path)
    assert result.returncode != 0
    assert "--verify" in result.err


def test_verify_and_output_cannot_be_combined(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"x")
    (tmp_path / "e.txt").write_text("00")
    result = dgst(*hmac_args(), "--verify", "e.txt", "--output", "o.txt", cwd=tmp_path)
    assert result.returncode != 0
    assert not (tmp_path / "o.txt").exists()


def test_hmac_and_cmac_cannot_be_combined(tmp_path):
    (tmp_path / "file.txt").write_bytes(b"x")
    result = dgst("--algorithm", "sha256", "--hmac", "--cmac", "--key", KEY, "--input", "file.txt", cwd=tmp_path)
    assert result.returncode != 0


def test_missing_input_file_with_hmac(tmp_path):
    result = dgst(*hmac_args(name="nope.txt"), cwd=tmp_path)
    assert result.returncode != 0
    assert "не найден" in result.err


# ---- AES-CMAC (бонус) ----

CMAC_KEY = "2b7e151628aed2a6abf7158809cf4f3c"


def test_cmac_matches_nist_vector(tmp_path):
    (tmp_path / "file.bin").write_bytes(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
    result = dgst("--cmac", "--key", CMAC_KEY, "--input", "file.bin", cwd=tmp_path)
    assert result.returncode == 0, result.err
    assert result.out == "070a16b46b4d4144f79bdd9dd04a287c  file.bin\n"


def test_cmac_accepts_algorithm_aes_and_empty_file(tmp_path):
    (tmp_path / "file.bin").write_bytes(b"")
    result = dgst("--algorithm", "aes", "--cmac", "--key", CMAC_KEY, "--input", "file.bin", cwd=tmp_path)
    assert result.out.split()[0] == "bb1d6929e95937287fa37d129b756746"


def test_cmac_rejects_hash_algorithm_and_bad_key_length(tmp_path):
    (tmp_path / "file.bin").write_bytes(b"x")
    assert dgst("--algorithm", "sha256", "--cmac", "--key", CMAC_KEY, "--input", "file.bin", cwd=tmp_path).returncode != 0
    result = dgst("--cmac", "--key", "aabb", "--input", "file.bin", cwd=tmp_path)
    assert result.returncode != 0
    assert "16 байт" in result.err


def test_aes_algorithm_requires_cmac(tmp_path):
    (tmp_path / "file.bin").write_bytes(b"x")
    assert dgst("--algorithm", "aes", "--input", "file.bin", cwd=tmp_path).returncode != 0


def test_cmac_verify_roundtrip_and_tamper(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(os.urandom(100))
    dgst("--cmac", "--key", CMAC_KEY, "--input", "file.bin", "--output", "mac.txt", cwd=tmp_path)

    ok = dgst("--cmac", "--key", CMAC_KEY, "--input", "file.bin", "--verify", "mac.txt", cwd=tmp_path)
    assert ok.returncode == 0 and "[OK] CMAC verification successful" in ok.out

    data = bytearray(target.read_bytes())
    data[50] ^= 0x80
    target.write_bytes(bytes(data))
    bad = dgst("--cmac", "--key", CMAC_KEY, "--input", "file.bin", "--verify", "mac.txt", cwd=tmp_path)
    assert bad.returncode == 1 and "[ERROR] CMAC verification failed" in bad.err


@pytest.mark.parametrize("size", [0, 5, 16, 17, 100, 5000])
def test_cmac_matches_reference(size, tmp_path):
    data = os.urandom(size)
    (tmp_path / "file.bin").write_bytes(data)
    result = dgst("--cmac", "--key", CMAC_KEY, "--input", "file.bin", cwd=tmp_path)
    expected = ReferenceCMAC.new(bytes.fromhex(CMAC_KEY), data, ciphermod=AES).hexdigest()
    assert result.out.split()[0] == expected


# ---- совместимость с OpenSSL ----

@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl не найден")
@pytest.mark.parametrize("size", [0, 10, 100000])
@pytest.mark.parametrize("key_bytes", [16, 64, 100])
def test_hmac_matches_openssl(size, key_bytes, tmp_path):
    key = os.urandom(key_bytes).hex()
    (tmp_path / "data.bin").write_bytes(os.urandom(size))
    mine = dgst(*hmac_args(key, "data.bin"), cwd=tmp_path).out.split()[0]
    system = subprocess.run(
        ["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"hexkey:{key}", "-r", "data.bin"],
        capture_output=True, cwd=tmp_path,
    ).stdout.decode().split()[0]
    assert mine == system


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl не найден")
@pytest.mark.parametrize("size", [0, 10, 100000])
def test_cmac_matches_openssl(size, tmp_path):
    (tmp_path / "data.bin").write_bytes(os.urandom(size))
    mine = dgst("--cmac", "--key", CMAC_KEY, "--input", "data.bin", cwd=tmp_path).out.split()[0]
    system = subprocess.run(
        ["openssl", "mac", "-cipher", "AES-128-CBC", "-macopt", f"hexkey:{CMAC_KEY}", "-in", "data.bin", "CMAC"],
        capture_output=True, cwd=tmp_path,
    ).stdout.decode().strip().lower()
    assert mine == system
