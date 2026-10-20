import os

import pytest

from cryptocore.hash.sha256 import SHA256
from cryptocore.hash.sha3_256 import SHA3_256


def differing_bits(hex1, hex2):
    bin1 = bin(int(hex1, 16))[2:].zfill(256)
    bin2 = bin(int(hex2, 16))[2:].zfill(256)
    return sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))


@pytest.mark.parametrize("algorithm", [SHA256, SHA3_256])
def test_avalanche_effect(algorithm):
    hash1 = algorithm().hash(b"Hello, world!")
    hash2 = algorithm().hash(b"Hello, world?")
    diff_count = differing_bits(hash1, hash2)
    assert 100 < diff_count < 156, f"Лавинный эффект слабый: изменилось {diff_count} бит"


@pytest.mark.parametrize("algorithm", [SHA256, SHA3_256])
def test_single_bit_flip_changes_about_half_of_output_bits(algorithm):
    total = 0
    trials = 40
    for i in range(trials):
        data = bytearray(os.urandom(64))
        original = algorithm().hash(bytes(data))
        data[i % 64] ^= 1 << (i % 8)
        total += differing_bits(original, algorithm().hash(bytes(data)))
    average = total / trials
    assert 120 < average < 136, f"в среднем изменилось {average:.1f} бит из 256"
