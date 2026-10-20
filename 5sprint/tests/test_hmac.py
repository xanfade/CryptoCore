import hashlib
import hmac as std_hmac
import os

import pytest

from cryptocore.mac.hmac import HMAC

# Тестовые векторы RFC 4231, раздел 4 (HMAC-SHA-256)
RFC_4231 = [
    ("1", "0b" * 20, b"Hi There".hex(),
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    ("2", b"Jefe".hex(), b"what do ya want for nothing?".hex(),
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ("3", "aa" * 20, "dd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    ("4", bytes(range(1, 26)).hex(), "cd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    ("6", "aa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First".hex(),
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    ("7", "aa" * 131,
     b"This is a test using a larger than block-size key and a larger than block-size data. "
     b"The key needs to be hashed before being used by the HMAC algorithm.".hex(),
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


@pytest.mark.parametrize("key,data,expected", [case[1:] for case in RFC_4231], ids=[case[0] for case in RFC_4231])
def test_rfc_4231_vectors(key, data, expected):
    assert HMAC(bytes.fromhex(key), "sha256").compute(bytes.fromhex(data)) == expected


def test_rfc_4231_case_5_truncated_to_128_bits():
    mac = HMAC(bytes.fromhex("0c" * 20), "sha256").compute(b"Test With Truncation")
    assert mac[:32] == "a3b6167473100ee06e0c796c2955552b"


@pytest.mark.parametrize("key_length", [16, 64, 100])
@pytest.mark.parametrize("hash_name,reference", [("sha256", hashlib.sha256), ("sha3-256", hashlib.sha3_256)])
def test_key_sizes_match_standard_library(key_length, hash_name, reference):
    key = os.urandom(key_length)
    message = os.urandom(500)
    assert HMAC(key, hash_name).compute(message) == std_hmac.new(key, message, reference).hexdigest()


def test_arbitrary_key_lengths_match_standard_library():
    for key_length in list(range(0, 140)) + [200, 500]:
        key = os.urandom(key_length)
        message = os.urandom(37)
        assert HMAC(key).compute(message) == std_hmac.new(key, message, hashlib.sha256).hexdigest()


def test_empty_message():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert HMAC(key).compute(b"") == std_hmac.new(key, b"", hashlib.sha256).hexdigest()
    assert HMAC(key).hexdigest() == HMAC(key).compute(b"")


def test_key_processing():
    block = 64
    assert HMAC(b"short").key == b"short" + bytes(block - 5)
    assert HMAC(bytes(range(64))).key == bytes(range(64))
    long_key = bytes(range(100))
    assert HMAC(long_key).key == hashlib.sha256(long_key).digest() + bytes(block - 32)
    assert HMAC(b"").key == bytes(block)


def test_sha3_uses_its_own_block_size():
    assert HMAC(b"k", "sha3-256").block_size == 136
    assert len(HMAC(b"k", "sha3-256").key) == 136


@pytest.mark.parametrize("chunk", [1, 7, 63, 64, 65, 1000])
def test_result_does_not_depend_on_chunk_size(chunk):
    key = os.urandom(20)
    message = os.urandom(1500)
    mac = HMAC(key)
    for i in range(0, len(message), chunk):
        mac.update(message[i:i + chunk])
    assert mac.hexdigest() == std_hmac.new(key, message, hashlib.sha256).hexdigest()


def test_digest_can_be_repeated_and_compute_does_not_change_state():
    key = b"key"
    mac = HMAC(key)
    mac.update(b"abc")
    first = mac.hexdigest()
    assert mac.hexdigest() == first
    assert mac.compute(b"other") == std_hmac.new(key, b"other", hashlib.sha256).hexdigest()
    assert mac.hexdigest() == first


def test_output_format():
    value = HMAC(b"k").hexdigest()
    assert len(value) == 64 and value == value.lower()
    assert len(HMAC(b"k").digest()) == 32


def test_unknown_hash_function_is_rejected():
    with pytest.raises(ValueError):
        HMAC(b"k", "md5")


def test_different_keys_and_messages_give_different_macs():
    assert HMAC(b"key1").compute(b"m") != HMAC(b"key2").compute(b"m")
    assert HMAC(b"key").compute(b"m1") != HMAC(b"key").compute(b"m2")
