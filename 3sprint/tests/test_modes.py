import os

import pytest
from Crypto.Cipher import AES

from cryptocore.modes import cbc, cfb, ctr, ofb

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

# Известные ответы из NIST SP 800-38A (AES-128)
NIST_CBC = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)
NIST_CFB = bytes.fromhex(
    "3b3fd92eb72dad20333449f8e83cfb4a"
    "c8a64537a0b3a93fcde3cdad9f1ce58b"
    "26751f67a3cbb140b1808cf187a4f4df"
    "c04b05357c5d1c0eeac4c66f9ff7f2e6"
)
NIST_OFB = bytes.fromhex(
    "3b3fd92eb72dad20333449f8e83cfb4a"
    "7789508d16918f03f53c52dac54ed825"
    "9740051e9c5fecf64344f7a82260edcc"
    "304c6528f659c77866a510d9c1d6ae5e"
)
NIST_CTR = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)

LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 100]


def reference(mode_name, iv):
    if mode_name == "cbc":
        return AES.new(KEY, AES.MODE_CBC, iv=iv)
    if mode_name == "cfb":
        return AES.new(KEY, AES.MODE_CFB, iv=iv, segment_size=128)
    if mode_name == "ofb":
        return AES.new(KEY, AES.MODE_OFB, iv=iv)
    return AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=iv)


def test_cbc_nist_vector():
    assert cbc.encrypt(KEY, PLAINTEXT, IV)[:64] == NIST_CBC


def test_cfb_nist_vector():
    assert cfb.encrypt(KEY, PLAINTEXT, IV) == NIST_CFB
    assert cfb.decrypt(KEY, NIST_CFB, IV) == PLAINTEXT


def test_ofb_nist_vector():
    assert ofb.encrypt(KEY, PLAINTEXT, IV) == NIST_OFB
    assert ofb.decrypt(KEY, NIST_OFB, IV) == PLAINTEXT


def test_ctr_nist_vector():
    assert ctr.encrypt(KEY, PLAINTEXT, CTR_IV) == NIST_CTR
    assert ctr.decrypt(KEY, NIST_CTR, CTR_IV) == PLAINTEXT


@pytest.mark.parametrize("mode", [cbc, cfb, ofb, ctr])
@pytest.mark.parametrize("length", LENGTHS)
def test_roundtrip(mode, length):
    data = os.urandom(length)
    iv = os.urandom(16)
    assert mode.decrypt(KEY, mode.encrypt(KEY, data, iv), iv) == data


@pytest.mark.parametrize("mode_name,mode", [("cbc", cbc), ("cfb", cfb), ("ofb", ofb), ("ctr", ctr)])
@pytest.mark.parametrize("length", LENGTHS)
def test_matches_pycryptodome(mode_name, mode, length):
    data = os.urandom(length)
    iv = os.urandom(16)
    if mode_name == "cbc":
        padding = 16 - length % 16
        expected = reference(mode_name, iv).encrypt(data + bytes([padding]) * padding)
    else:
        expected = reference(mode_name, iv).encrypt(data)
    assert mode.encrypt(KEY, data, iv) == expected


@pytest.mark.parametrize("mode", [cfb, ofb, ctr])
@pytest.mark.parametrize("length", [0, 1, 5, 16, 17, 40])
def test_stream_modes_keep_length(mode, length):
    assert len(mode.encrypt(KEY, bytes(length), IV)) == length


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17])
def test_cbc_pads_to_block_size(length):
    ciphertext = cbc.encrypt(KEY, bytes(length), IV)
    assert len(ciphertext) == (length // 16 + 1) * 16


def test_ctr_counter_wraps_around():
    iv = b"\xff" * 16
    data = bytes(48)
    expected = reference("ctr", iv).encrypt(data)
    assert ctr.encrypt(KEY, data, iv) == expected
    primitive = AES.new(KEY, AES.MODE_ECB)
    assert ctr.encrypt(KEY, data, iv)[16:32] == primitive.encrypt(bytes(16))


@pytest.mark.parametrize("mode", [cbc, cfb, ofb, ctr])
def test_wrong_iv_length_is_rejected(mode):
    with pytest.raises(ValueError):
        mode.encrypt(KEY, b"data", bytes(8))
    with pytest.raises(ValueError):
        mode.decrypt(KEY, bytes(16), bytes(8))


@pytest.mark.parametrize("bad", [b"", bytes(10)])
def test_cbc_decrypt_rejects_bad_length(bad):
    with pytest.raises(ValueError):
        cbc.decrypt(KEY, bad, IV)


def test_cbc_decrypt_rejects_invalid_padding():
    # блок открытого текста из нулей заканчивается байтом 0x00 — это некорректное дополнение
    ciphertext = AES.new(KEY, AES.MODE_ECB).encrypt(IV)
    with pytest.raises(ValueError):
        cbc.decrypt(KEY, ciphertext, IV)
