import pytest

from cryptocore.key_checks import weak_key_reason


@pytest.mark.parametrize("key", [
    bytes(16),
    b"\xff" * 16,
    b"\x41" * 16,
    bytes(range(16)),
    bytes(range(0xf0, 0x100)),
    bytes(range(15, -1, -1)),
    bytes((250 + i) % 256 for i in range(16)),
])
def test_weak_keys_are_detected(key):
    assert weak_key_reason(key) is not None


@pytest.mark.parametrize("key", [
    bytes.fromhex("1a2b3c4d5e6f7890fedcba9876543210"),
    bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    bytes(range(8)) + bytes(range(8)),
])
def test_normal_keys_are_not_flagged(key):
    assert weak_key_reason(key) is None


def test_reason_texts_are_specific():
    assert "нулев" in weak_key_reason(bytes(16))
    assert "одинаков" in weak_key_reason(b"\x41" * 16)
    assert "возрастанию" in weak_key_reason(bytes(range(16)))
    assert "убыванию" in weak_key_reason(bytes(range(15, -1, -1)))
