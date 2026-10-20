import hashlib
import os
import shutil
import subprocess
import sys

import pytest

from tests.helpers import KEY, SRC_DIR, run_cryptocore

ALGORITHMS = {"sha256": hashlib.sha256, "sha3-256": hashlib.sha3_256}


def dgst(*args, cwd=None, stdin=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "cryptocore", "dgst", *args],
        input=stdin, capture_output=True, env=env, cwd=cwd,
    )


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("size", [0, 1, 55, 56, 64, 135, 136, 1000, 20000])
def test_output_format_and_value(algorithm, size, tmp_path):
    data = os.urandom(size)
    (tmp_path / "file.bin").write_bytes(data)

    result = dgst("--algorithm", algorithm, "--input", "file.bin", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    expected = f"{ALGORITHMS[algorithm](data).hexdigest()}  file.bin\n"
    assert result.stdout.decode("utf-8") == expected
    assert b"\r" not in result.stdout


@pytest.mark.parametrize("algorithm,expected", [
    ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("sha3-256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
])
def test_empty_file(algorithm, expected, tmp_path):
    (tmp_path / "empty").write_bytes(b"")
    result = dgst("--algorithm", algorithm, "--input", "empty", cwd=tmp_path)
    assert result.stdout.decode().split()[0] == expected


def test_stdin_input_matches_nist_vectors():
    result = dgst("--algorithm", "sha256", "--input", "-", stdin=b"abc")
    assert result.stdout.decode() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -\n"

    long_message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    result = dgst("--algorithm", "sha256", "--input", "-", stdin=long_message)
    assert result.stdout.decode() == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1  -\n"


def test_output_flag_writes_same_line_to_file(tmp_path):
    (tmp_path / "backup.tar").write_bytes(b"data to hash")

    to_stdout = dgst("--algorithm", "sha3-256", "--input", "backup.tar", cwd=tmp_path)
    to_file = dgst("--algorithm", "sha3-256", "--input", "backup.tar", "--output", "backup.sha3", cwd=tmp_path)

    assert to_file.returncode == 0, to_file.stderr
    assert to_file.stdout == b""
    assert (tmp_path / "backup.sha3").read_bytes() == to_stdout.stdout


def test_missing_input_file_gives_clear_error(tmp_path):
    result = dgst("--algorithm", "sha256", "--input", "nope.bin", cwd=tmp_path)
    assert result.returncode != 0
    assert "не найден" in result.stderr.decode("utf-8")
    assert result.stdout == b""


def test_directory_as_input_is_an_error(tmp_path):
    result = dgst("--algorithm", "sha256", "--input", str(tmp_path))
    assert result.returncode != 0


def test_unwritable_output_gives_error(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    result = dgst("--algorithm", "sha256", "--input", "f", "--output", "no_such_dir/out.txt", cwd=tmp_path)
    assert result.returncode == 1
    assert "не удалось записать" in result.stderr.decode("utf-8")


@pytest.mark.parametrize("extra", [
    ["--mode", "cbc"],
    ["--encrypt"],
    ["--decrypt"],
    ["--iv", "00" * 16],
])
def test_encryption_arguments_are_rejected(extra, tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    result = dgst("--algorithm", "sha256", "--input", "f", *extra, cwd=tmp_path)
    assert result.returncode != 0
    assert b"unrecognized arguments" in result.stderr


def test_key_without_hmac_or_cmac_is_rejected(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    result = dgst("--algorithm", "sha256", "--input", "f", "--key", KEY, cwd=tmp_path)
    assert result.returncode != 0
    assert "--hmac" in result.stderr.decode("utf-8")


def test_unknown_algorithm_is_rejected(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    assert dgst("--algorithm", "md5", "--input", "f", cwd=tmp_path).returncode != 0


def test_required_arguments(tmp_path):
    assert dgst("--input", "f", cwd=tmp_path).returncode != 0
    assert dgst("--algorithm", "sha256", cwd=tmp_path).returncode != 0


def test_encryption_still_works_after_adding_dgst(tmp_path):
    (tmp_path / "p.txt").write_bytes(b"still works")
    assert run_cryptocore(
        "--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", "1a2b3c4d5e6f7890fedcba9876543210",
        "--input", str(tmp_path / "p.txt"), "--output", str(tmp_path / "c.bin"),
    ).returncode == 0


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="sha256sum не найден")
@pytest.mark.parametrize("size", [0, 3, 10000, 300000])
def test_matches_sha256sum_output_exactly(size, tmp_path):
    (tmp_path / "data.bin").write_bytes(os.urandom(size))
    mine = dgst("--algorithm", "sha256", "--input", "data.bin", cwd=tmp_path).stdout
    system = subprocess.run(["sha256sum", "--text", "data.bin"], capture_output=True, cwd=tmp_path).stdout
    assert mine == system


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl не найден")
@pytest.mark.parametrize("size", [0, 3, 10000, 100000])
def test_sha3_matches_openssl(size, tmp_path):
    (tmp_path / "data.bin").write_bytes(os.urandom(size))
    mine = dgst("--algorithm", "sha3-256", "--input", "data.bin", cwd=tmp_path).stdout.decode().split()[0]
    system = subprocess.run(
        ["openssl", "dgst", "-sha3-256", "-r", "data.bin"], capture_output=True, cwd=tmp_path
    ).stdout.decode().split()[0]
    assert mine == system
