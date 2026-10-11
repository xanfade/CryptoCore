import hashlib
import os

import pytest

from cryptocore.hash import sha3_256 as sha3_module
from cryptocore.hash.sha3_256 import SHA3_256

# Тестовые векторы NIST (FIPS 202, примеры SHA3-256)
NIST_VECTORS = [
    (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
    ),
    (b"a" * 1_000_000, "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
]


@pytest.mark.parametrize(
    "message,expected", NIST_VECTORS, ids=["empty", "abc", "448-bit", "896-bit", "million-a"]
)
def test_nist_vectors(message, expected):
    assert SHA3_256(message).hexdigest() == expected


def test_round_constants():
    constants = sha3_module.ROUND_CONSTANTS
    assert len(constants) == 24
    assert constants[:3] == [0x0000000000000001, 0x0000000000008082, 0x800000000000808A]
    assert constants[-1] == 0x8000000080008008


@pytest.mark.parametrize("length", [0, 1, 134, 135, 136, 137, 271, 272, 273, 1000])
def test_rate_boundaries_match_hashlib(length):
    data = os.urandom(length)
    assert SHA3_256(data).hexdigest() == hashlib.sha3_256(data).hexdigest()


@pytest.mark.parametrize("chunk", [1, 5, 135, 136, 137, 500])
def test_result_does_not_depend_on_chunk_size(chunk):
    data = os.urandom(700)
    hasher = SHA3_256()
    for i in range(0, len(data), chunk):
        hasher.update(data[i:i + chunk])
    assert hasher.hexdigest() == hashlib.sha3_256(data).hexdigest()


def test_digest_can_be_called_repeatedly_and_update_continues():
    hasher = SHA3_256(b"abc")
    first = hasher.hexdigest()
    assert hasher.hexdigest() == first
    hasher.update(b"def")
    assert hasher.hexdigest() == hashlib.sha3_256(b"abcdef").hexdigest()


def test_output_is_lowercase_hex_of_64_chars():
    value = SHA3_256(b"x").hexdigest()
    assert len(value) == 64 and value == value.lower()
    assert len(SHA3_256(b"x").digest()) == 32
