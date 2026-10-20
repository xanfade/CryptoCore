import ast
from pathlib import Path

import pytest

from cryptocore import csprng
from cryptocore.csprng import CSPRNGError, generate_random_bytes
from scripts.generate_nist_data import generate_file

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def test_returns_requested_number_of_bytes():
    for size in (0, 1, 16, 4096):
        data = generate_random_bytes(size)
        assert isinstance(data, bytes)
        assert len(data) == size


def test_key_uniqueness():
    keys = set()
    for _ in range(1000):
        key = generate_random_bytes(16).hex()
        assert key not in keys, f"Найден дубликат ключа: {key}"
        keys.add(key)
    assert len(keys) == 1000


def test_average_hamming_weight_is_close_to_half():
    keys = [generate_random_bytes(16) for _ in range(1000)]
    ones = sum(bin(int.from_bytes(key, "big")).count("1") for key in keys)
    ratio = ones / (1000 * 128)
    assert 0.49 < ratio < 0.51, f"доля единичных бит: {ratio:.4f}"


def test_every_byte_value_appears_in_large_sample():
    assert len(set(generate_random_bytes(65536))) == 256


@pytest.mark.parametrize("bad", [-1, 1.5, "16", None, True])
def test_invalid_argument_is_rejected(bad):
    with pytest.raises(ValueError):
        generate_random_bytes(bad)


def test_uses_os_urandom(monkeypatch):
    monkeypatch.setattr(csprng.os, "urandom", lambda n: b"\x07" * n)
    assert generate_random_bytes(5) == b"\x07" * 5


def test_os_failure_gives_clear_error(monkeypatch):
    def broken(n):
        raise OSError("устройство недоступно")

    monkeypatch.setattr(csprng.os, "urandom", broken)
    with pytest.raises(CSPRNGError) as exc_info:
        generate_random_bytes(16)
    assert "os.urandom" in str(exc_info.value)
    assert "устройство недоступно" in str(exc_info.value)


def test_short_read_gives_clear_error(monkeypatch):
    monkeypatch.setattr(csprng.os, "urandom", lambda n: b"\x00" * (n - 1))
    with pytest.raises(CSPRNGError):
        generate_random_bytes(16)


def test_package_does_not_use_random_module():
    for path in SRC_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            assert "random" not in names, f"{path} использует модуль random"


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 10_000])
def test_generate_nist_file_has_exact_size(size, tmp_path):
    target = tmp_path / "nist.bin"
    assert generate_file(target, size) == size
    assert target.stat().st_size == size
