"""Упрощённая самопроверка по NIST SP 800-22: тесты frequency (monobit), runs и cumulative sums.

Это НЕ замена официальному NIST STS (там 15 тестов), а быстрая проверка на чистом Python.
"""
import argparse
import math
import sys

POPCOUNT = [bin(i).count("1") for i in range(256)]


def popcount_bytes(data: bytes) -> int:
    return sum(map(POPCOUNT.__getitem__, data))


def popcount_int(x: int) -> int:
    if hasattr(x, "bit_count"):
        return x.bit_count()
    return bin(x).count("1")


def normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def frequency_test(data: bytes) -> float:
    n = len(data) * 8
    s = 2 * popcount_bytes(data) - n
    return math.erfc(abs(s) / math.sqrt(n) / math.sqrt(2.0))


def runs_test(data: bytes) -> float:
    n = len(data) * 8
    ones = popcount_bytes(data)
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    x = int.from_bytes(data, "big")
    transitions = popcount_int((x ^ (x >> 1)) & ((1 << (n - 1)) - 1))
    v_obs = transitions + 1
    return math.erfc(abs(v_obs - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


def byte_walk_tables(reverse_bits: bool):
    total, max_prefix, min_prefix = [], [], []
    for value in range(256):
        bits = [(value >> (7 - i)) & 1 for i in range(8)]
        if reverse_bits:
            bits.reverse()
        s = best = worst = 0
        first = True
        for bit in bits:
            s += 1 if bit else -1
            if first:
                best = worst = s
                first = False
            else:
                best, worst = max(best, s), min(worst, s)
        total.append(s)
        max_prefix.append(best)
        min_prefix.append(worst)
    return total, max_prefix, min_prefix


def max_excursion(data: bytes, reverse: bool) -> int:
    total, max_prefix, min_prefix = byte_walk_tables(reverse)
    sequence = reversed(data) if reverse else data
    s = high = low = 0
    for b in sequence:
        high = max(high, s + max_prefix[b])
        low = min(low, s + min_prefix[b])
        s += total[b]
    return max(high, -low)


def cusum_p_value(n: int, z: int) -> float:
    sqrt_n = math.sqrt(n)
    first_start = math.floor((-n / z + 1) / 4)
    first_end = math.floor((n / z - 1) / 4)
    second_start = math.floor((-n / z - 3) / 4)

    total = 0.0
    for k in range(first_start, first_end + 1):
        total += normal_cdf((4 * k + 1) * z / sqrt_n) - normal_cdf((4 * k - 1) * z / sqrt_n)
    p = 1.0 - total

    total = 0.0
    for k in range(second_start, first_end + 1):
        total += normal_cdf((4 * k + 3) * z / sqrt_n) - normal_cdf((4 * k + 1) * z / sqrt_n)
    return p + total


def cusum_test(data: bytes, reverse: bool = False) -> float:
    return cusum_p_value(len(data) * 8, max_excursion(data, reverse))


def bits_to_bytes(bits: str) -> bytes:
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def split_sequences(data: bytes, sequence_bytes: int):
    count = len(data) // sequence_bytes
    return [data[i * sequence_bytes:(i + 1) * sequence_bytes] for i in range(count)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Файл с двоичными случайными данными.")
    parser.add_argument("--sequence-bytes", type=int, default=125_000,
                        help="Размер одной последовательности в байтах (по умолчанию 125000 = 1 000 000 бит).")
    parser.add_argument("--alpha", type=float, default=0.01)
    args = parser.parse_args(argv)

    with open(args.input, "rb") as f:
        data = f.read()
    sequences = split_sequences(data, args.sequence_bytes)
    if not sequences:
        print("Файл меньше одной последовательности", file=sys.stderr)
        return 1

    tests = [
        ("frequency (monobit)", frequency_test),
        ("runs", runs_test),
        ("cumulative sums (forward)", lambda s: cusum_test(s, False)),
        ("cumulative sums (reverse)", lambda s: cusum_test(s, True)),
    ]
    print(f"Файл: {args.input}, размер: {len(data)} байт, последовательностей: {len(sequences)} "
          f"по {args.sequence_bytes * 8} бит, alpha = {args.alpha}")
    for name, test in tests:
        p_values = [test(s) for s in sequences]
        passed = sum(1 for p in p_values if p >= args.alpha)
        print(f"{name:28s} прошло {passed}/{len(sequences)}  "
              f"(min p = {min(p_values):.4f}, среднее p = {sum(p_values) / len(p_values):.4f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
