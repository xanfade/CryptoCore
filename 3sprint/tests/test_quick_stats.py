import math
import random

from cryptocore.csprng import generate_random_bytes
from scripts import quick_stats as q

# Пример из NIST SP 800-22 (n = 100 бит)
NIST_EXAMPLE = (
    "1100100100001111110110101010001000100001011010001100001000110100"
    "110001001100011001100010100010111000"
)


def naive_frequency(bits):
    n = len(bits)
    return math.erfc(abs(sum(2 * b - 1 for b in bits)) / math.sqrt(n) / math.sqrt(2))


def naive_runs(bits):
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + sum(bits[i] != bits[i + 1] for i in range(n - 1))
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


def naive_cusum(bits):
    s = z = 0
    for b in bits:
        s += 2 * b - 1
        z = max(z, abs(s))
    return q.cusum_p_value(len(bits), z)


def to_bits(data):
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def test_naive_reference_matches_nist_published_values():
    bits = [int(c) for c in NIST_EXAMPLE]
    assert round(naive_frequency(bits), 6) == 0.109599
    assert round(naive_runs(bits), 6) == 0.500798
    assert round(naive_cusum(bits), 6) == 0.219194
    assert round(naive_cusum(bits[::-1]), 6) == 0.114866


def test_fast_implementation_matches_naive_reference():
    rng = random.Random(12345)
    for size in (1, 2, 7, 64, 500):
        data = bytes(rng.randrange(256) for _ in range(size))
        bits = to_bits(data)
        assert math.isclose(q.frequency_test(data), naive_frequency(bits), rel_tol=1e-9)
        assert math.isclose(q.runs_test(data), naive_runs(bits), rel_tol=1e-9, abs_tol=1e-12)
        assert math.isclose(q.cusum_test(data, False), naive_cusum(bits), rel_tol=1e-9)
        assert math.isclose(q.cusum_test(data, True), naive_cusum(bits[::-1]), rel_tol=1e-9)


def test_obviously_bad_data_fails():
    assert q.frequency_test(bytes(1000)) < 0.01
    assert q.runs_test(bytes([0xAA]) * 1000) < 0.01
    assert q.cusum_test(bytes(1000)) < 0.01


def test_csprng_output_passes():
    data = generate_random_bytes(125_000)
    # порог мал, чтобы тест не падал случайно у настоящего генератора
    assert q.frequency_test(data) > 1e-6
    assert q.runs_test(data) > 1e-6
    assert q.cusum_test(data, False) > 1e-6
    assert q.cusum_test(data, True) > 1e-6
