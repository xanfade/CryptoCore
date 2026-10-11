import hashlib
import os

import pytest

from cryptocore.hash import sha256 as sha256_module
from cryptocore.hash.sha256 import SHA256

# Тестовые векторы NIST (FIPS 180-4 / SHAVS)
NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
    (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]

FIPS_ROUND_CONSTANTS = [
    "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
    "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
    "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
    "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
    "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
    "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
    "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
    "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2",
]


@pytest.mark.parametrize(
    "message,expected", NIST_VECTORS, ids=["empty", "abc", "448-bit", "896-bit", "million-a"]
)
def test_nist_vectors(message, expected):
    assert SHA256(message).hexdigest() == expected


def test_initial_hash_values_are_derived_correctly():
    assert sha256_module.INITIAL_HASH == [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]


def test_round_constants_are_derived_correctly():
    assert sha256_module.ROUND_CONSTANTS == [int(c, 16) for c in FIPS_ROUND_CONSTANTS]


@pytest.mark.parametrize("length", [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000])
def test_padding_boundaries_match_hashlib(length):
    data = os.urandom(length)
    assert SHA256(data).hexdigest() == hashlib.sha256(data).hexdigest()


def test_padding_is_multiple_of_block_size_and_encodes_length():
    for length in range(0, 200):
        pad = SHA256().padding(length)
        assert (length + len(pad)) % 64 == 0
        assert pad[0] == 0x80
        assert int.from_bytes(pad[-8:], "big") == length * 8


def test_random_lengths_match_hashlib():
    for length in range(0, 260, 7):
        data = os.urandom(length)
        assert SHA256(data).hexdigest() == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("chunk", [1, 3, 17, 63, 64, 65, 200])
def test_result_does_not_depend_on_chunk_size(chunk):
    data = os.urandom(777)
    hasher = SHA256()
    for i in range(0, len(data), chunk):
        hasher.update(data[i:i + chunk])
    assert hasher.hexdigest() == hashlib.sha256(data).hexdigest()


def test_digest_can_be_called_repeatedly_and_update_continues():
    hasher = SHA256(b"abc")
    first = hasher.hexdigest()
    assert hasher.hexdigest() == first
    hasher.update(b"def")
    assert hasher.hexdigest() == hashlib.sha256(b"abcdef").hexdigest()


def test_output_is_lowercase_hex_of_64_chars():
    value = SHA256(b"x").hexdigest()
    assert len(value) == 64
    assert value == value.lower()
    assert set(value) <= set("0123456789abcdef")
    assert len(SHA256(b"x").digest()) == 32
