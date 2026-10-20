import hashlib
import hmac as std_hmac
import io
import os

import pytest

from cryptocore.aead import AEAD, AuthenticationError, EncryptThenMAC
from cryptocore.aead import etm as etm_module
from cryptocore.aead.kdf import hkdf_sha256

MODES = ["ctr", "cbc", "cfb", "ofb"]
MASTER = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_hkdf_rfc_5869_test_case_1():
    okm = hkdf_sha256(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
        bytes.fromhex("000102030405060708090a0b0c"),
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_without_salt_matches_standard_library_construction():
    ikm, info = os.urandom(22), b"info"
    prk = std_hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    expected = std_hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    assert hkdf_sha256(ikm, info, 32) == expected


@pytest.mark.parametrize("length", [0, 1, 32, 33, 64, 100])
def test_hkdf_output_length(length):
    assert len(hkdf_sha256(b"key", b"info", length)) == length


def test_hkdf_rejects_too_long_output():
    with pytest.raises(ValueError):
        hkdf_sha256(b"key", b"info", 255 * 32 + 1)


def test_etm_is_an_aead():
    assert isinstance(EncryptThenMAC(MASTER), AEAD)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 100, 1000])
def test_roundtrip(mode, length):
    etm = EncryptThenMAC(MASTER, mode)
    plaintext, aad = os.urandom(length), os.urandom(9)
    assert etm.decrypt(etm.encrypt(plaintext, aad), aad) == plaintext


@pytest.mark.parametrize("mode", MODES)
def test_empty_aad(mode):
    etm = EncryptThenMAC(MASTER, mode)
    assert etm.decrypt(etm.encrypt(b"message")) == b"message"
    assert etm.decrypt(etm.encrypt(b"message", b""), b"") == b"message"


@pytest.mark.parametrize("mode", MODES)
def test_wrong_aad_fails_and_returns_nothing(mode):
    etm = EncryptThenMAC(MASTER, mode)
    data = etm.encrypt(b"Secret message", b"correct_aad")
    result = None
    with pytest.raises(AuthenticationError):
        result = etm.decrypt(data, b"wrong_aad")
    assert result is None


@pytest.mark.parametrize("mode", MODES)
def test_every_single_bit_flip_is_detected(mode):
    etm = EncryptThenMAC(MASTER, mode)
    data = etm.encrypt(b"Another secret message", b"aad")
    for index in range(len(data)):
        for bit in range(8):
            tampered = bytearray(data)
            tampered[index] ^= 1 << bit
            with pytest.raises(AuthenticationError):
                etm.decrypt(bytes(tampered), b"aad")


def test_wrong_master_key_fails():
    data = EncryptThenMAC(MASTER).encrypt(b"message", b"aad")
    with pytest.raises(AuthenticationError):
        EncryptThenMAC(bytes(16)).decrypt(data, b"aad")


def test_truncated_and_extended_input_fail():
    etm = EncryptThenMAC(MASTER)
    data = etm.encrypt(b"message", b"aad")
    for tampered in (data[:-1], data + b"\x00", data[1:], b"", data[:47]):
        with pytest.raises(AuthenticationError):
            etm.decrypt(tampered, b"aad")


def test_tag_is_checked_before_decryption_even_for_cbc(monkeypatch):
    etm = EncryptThenMAC(MASTER, "cbc")
    data = bytearray(etm.encrypt(b"message", b"aad"))
    data[20] ^= 1

    def forbidden(*args, **kwargs):
        raise AssertionError("расшифрование началось до проверки тега")

    monkeypatch.setitem(etm_module.MODES, "cbc", type("Stub", (), {"encrypt": forbidden, "decrypt": forbidden}))
    with pytest.raises(AuthenticationError):
        etm.decrypt(bytes(data), b"aad")


def test_aad_and_ciphertext_boundary_is_unambiguous():
    etm = EncryptThenMAC(MASTER)
    data = etm.encrypt(b"message", b"")
    body, tag = data[:-32], data[-32:]
    # попытка выдать часть шифртекста за AAD и наоборот не должна проходить проверку
    with pytest.raises(AuthenticationError):
        etm.decrypt(body[:-1] + tag, body[-1:])
    with pytest.raises(AuthenticationError):
        etm.decrypt(body + tag, b"extra")


def test_key_separation():
    etm = EncryptThenMAC(MASTER, "ctr")
    assert etm.enc_key != MASTER
    assert etm.mac_key != MASTER
    assert etm.enc_key != etm.mac_key[:16]
    assert len(etm.enc_key) == 16 and len(etm.mac_key) == 32
    assert EncryptThenMAC(MASTER, "cbc").enc_key != etm.enc_key
    assert EncryptThenMAC(MASTER, "ctr").mac_key == etm.mac_key  # детерминированный вывод


def test_output_layout_and_fresh_iv_each_time():
    etm = EncryptThenMAC(MASTER, "ctr")
    first, second = etm.encrypt(b"x" * 20), etm.encrypt(b"x" * 20)
    assert len(first) == 16 + 20 + 32
    assert first[:16] != second[:16]
    assert first != second


def test_iv_comes_from_csprng_function(monkeypatch):
    monkeypatch.setattr(etm_module, "generate_random_bytes", lambda n: b"\x33" * n)
    assert EncryptThenMAC(MASTER).encrypt(b"x")[:16] == b"\x33" * 16


def test_streaming_aad():
    etm = EncryptThenMAC(MASTER)
    aad = os.urandom(5000)
    data = etm.encrypt(b"payload", aad)
    chunks = [aad[i:i + 333] for i in range(0, len(aad), 333)]
    assert etm.decrypt(data, chunks) == b"payload"
    assert etm.decrypt(data, io.BytesIO(aad)) == b"payload"


def test_invalid_parameters():
    with pytest.raises(ValueError):
        EncryptThenMAC(MASTER, "ecb")
    with pytest.raises(ValueError):
        EncryptThenMAC(b"")
