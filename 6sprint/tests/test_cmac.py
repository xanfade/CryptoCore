import os

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from cryptocore.mac.cmac import AESCMAC

# Векторы RFC 4493 / NIST SP 800-38B, пример AES-128
KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
VECTORS = [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
]


@pytest.mark.parametrize("length,expected", VECTORS)
def test_nist_vectors(length, expected):
    assert AESCMAC(KEY).compute(MESSAGE[:length]) == expected


def test_subkey_generation():
    mac = AESCMAC(KEY)
    assert mac._k1.hex() == "fbeed618357133667c85e08f7236a8de"
    assert mac._k2.hex() == "f7ddac306ae266ccf90bc11ee46d513b"


@pytest.mark.parametrize("length", list(range(0, 70)) + [160, 1000])
def test_matches_reference_implementation(length):
    key = os.urandom(16)
    message = os.urandom(length)
    expected = ReferenceCMAC.new(key, message, ciphermod=AES).hexdigest()
    assert AESCMAC(key).compute(message) == expected


@pytest.mark.parametrize("chunk", [1, 5, 15, 16, 17, 100])
def test_result_does_not_depend_on_chunk_size(chunk):
    message = os.urandom(333)
    mac = AESCMAC(KEY)
    for i in range(0, len(message), chunk):
        mac.update(message[i:i + chunk])
    assert mac.hexdigest() == ReferenceCMAC.new(KEY, message, ciphermod=AES).hexdigest()


def test_digest_can_be_repeated_and_compute_does_not_change_state():
    mac = AESCMAC(KEY)
    mac.update(MESSAGE[:20])
    first = mac.hexdigest()
    assert mac.hexdigest() == first
    assert mac.compute(b"zzz") == ReferenceCMAC.new(KEY, MESSAGE[:20] + b"zzz", ciphermod=AES).hexdigest()
    assert mac.hexdigest() == first


@pytest.mark.parametrize("length", [0, 8, 15, 17, 32])
def test_key_must_be_16_bytes(length):
    with pytest.raises(ValueError):
        AESCMAC(bytes(length))
