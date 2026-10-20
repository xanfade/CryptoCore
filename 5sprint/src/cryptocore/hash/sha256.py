import math
import struct

MASK = 0xFFFFFFFF
# x * DOUBLE даёт слово, записанное дважды подряд: циклический сдвиг = обычный сдвиг вправо
DOUBLE = (1 << 32) + 1
BLOCK_SIZE = 64


def _first_primes(count):
    primes = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def _icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


_PRIMES = _first_primes(64)

# Дробные части квадратных корней первых 8 простых чисел (FIPS 180-4, п. 5.3.3)
INITIAL_HASH = [math.isqrt(p << 64) & MASK for p in _PRIMES[:8]]

# Дробные части кубических корней первых 64 простых чисел (FIPS 180-4, п. 4.2.2)
ROUND_CONSTANTS = [_icbrt(p << 96) & MASK for p in _PRIMES]


def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x = w[i - 15]
        y = w[i - 2]
        xx = x * DOUBLE
        yy = y * DOUBLE
        s0 = ((xx >> 7) ^ (xx >> 18) ^ (x >> 3)) & MASK
        s1 = ((yy >> 17) ^ (yy >> 19) ^ (y >> 10)) & MASK
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)

    a, b, c, d, e, f, g, h = state
    k = ROUND_CONSTANTS
    for i in range(0, 64, 8):
        ee = e * DOUBLE
        t1 = (h + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (g ^ (e & (f ^ g))) + k[i + 0] + w[i + 0]) & MASK
        d = (d + t1) & MASK
        aa = a * DOUBLE
        h = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((a & b) | (c & (a | b)))) & MASK
        ee = d * DOUBLE
        t1 = (g + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (f ^ (d & (e ^ f))) + k[i + 1] + w[i + 1]) & MASK
        c = (c + t1) & MASK
        aa = h * DOUBLE
        g = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((h & a) | (b & (h | a)))) & MASK
        ee = c * DOUBLE
        t1 = (f + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (e ^ (c & (d ^ e))) + k[i + 2] + w[i + 2]) & MASK
        b = (b + t1) & MASK
        aa = g * DOUBLE
        f = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((g & h) | (a & (g | h)))) & MASK
        ee = b * DOUBLE
        t1 = (e + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (d ^ (b & (c ^ d))) + k[i + 3] + w[i + 3]) & MASK
        a = (a + t1) & MASK
        aa = f * DOUBLE
        e = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((f & g) | (h & (f | g)))) & MASK
        ee = a * DOUBLE
        t1 = (d + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (c ^ (a & (b ^ c))) + k[i + 4] + w[i + 4]) & MASK
        h = (h + t1) & MASK
        aa = e * DOUBLE
        d = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((e & f) | (g & (e | f)))) & MASK
        ee = h * DOUBLE
        t1 = (c + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (b ^ (h & (a ^ b))) + k[i + 5] + w[i + 5]) & MASK
        g = (g + t1) & MASK
        aa = d * DOUBLE
        c = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((d & e) | (f & (d | e)))) & MASK
        ee = g * DOUBLE
        t1 = (b + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (a ^ (g & (h ^ a))) + k[i + 6] + w[i + 6]) & MASK
        f = (f + t1) & MASK
        aa = c * DOUBLE
        b = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((c & d) | (e & (c | d)))) & MASK
        ee = f * DOUBLE
        t1 = (a + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & MASK) + (h ^ (f & (g ^ h))) + k[i + 7] + w[i + 7]) & MASK
        e = (e + t1) & MASK
        aa = b * DOUBLE
        a = (t1 + (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & MASK) + ((b & c) | (d & (b | c)))) & MASK

    return [
        (state[0] + a) & MASK, (state[1] + b) & MASK, (state[2] + c) & MASK, (state[3] + d) & MASK,
        (state[4] + e) & MASK, (state[5] + f) & MASK, (state[6] + g) & MASK, (state[7] + h) & MASK,
    ]


class SHA256:
    digest_size = 32
    block_size = BLOCK_SIZE

    def __init__(self, data=b""):
        self.h = list(INITIAL_HASH)
        self.k = ROUND_CONSTANTS
        self._buffer = b""
        self._length = 0
        if data:
            self.update(data)

    def padding(self, message_length):
        # бит '1', затем нули, затем длина сообщения в битах (64 бита)
        zeros = (55 - message_length) % BLOCK_SIZE
        return b"\x80" + b"\x00" * zeros + struct.pack(">Q", (message_length * 8) & 0xFFFFFFFFFFFFFFFF)

    def process_block(self, block):
        self.h = _compress(self.h, block)

    def update(self, message):
        self._length += len(message)
        data = self._buffer + message
        full = len(data) - len(data) % BLOCK_SIZE
        for offset in range(0, full, BLOCK_SIZE):
            self.process_block(data[offset:offset + BLOCK_SIZE])
        self._buffer = data[full:]

    def digest(self):
        state = list(self.h)
        tail = self._buffer + self.padding(self._length)
        for offset in range(0, len(tail), BLOCK_SIZE):
            state = _compress(state, tail[offset:offset + BLOCK_SIZE])
        return struct.pack(">8I", *state)

    def hexdigest(self):
        return self.digest().hex()

    def hash(self, message):
        self.update(message)
        return self.hexdigest()
