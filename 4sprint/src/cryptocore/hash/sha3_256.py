import struct

MASK = 0xFFFFFFFFFFFFFFFF
RATE = 136  # 1088 бит = 1600 - 2 * 256
STATE_LANES = 25


def _round_constants():
    def rc_bit(t):
        if t % 255 == 0:
            return 1
        r = [1, 0, 0, 0, 0, 0, 0, 0]
        for _ in range(t % 255):
            r = [0] + r
            r[0] ^= r[8]
            r[4] ^= r[8]
            r[5] ^= r[8]
            r[6] ^= r[8]
            r = r[:8]
        return r[0]

    constants = []
    for ir in range(24):
        value = 0
        for j in range(7):
            value |= rc_bit(7 * ir + j) << ((1 << j) - 1)
        constants.append(value)
    return constants


ROUND_CONSTANTS = _round_constants()


def keccak_f(a):
    (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = a
    for rc in ROUND_CONSTANTS:
        c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
        c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
        c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
        c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
        c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & MASK)
        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & MASK)
        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & MASK)
        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & MASK)
        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & MASK)
        b0 = a0 ^ d0
        v = a5 ^ d0
        b16 = ((v << 36) | (v >> 28)) & MASK
        v = a10 ^ d0
        b7 = ((v << 3) | (v >> 61)) & MASK
        v = a15 ^ d0
        b23 = ((v << 41) | (v >> 23)) & MASK
        v = a20 ^ d0
        b14 = ((v << 18) | (v >> 46)) & MASK
        v = a1 ^ d1
        b10 = ((v << 1) | (v >> 63)) & MASK
        v = a6 ^ d1
        b1 = ((v << 44) | (v >> 20)) & MASK
        v = a11 ^ d1
        b17 = ((v << 10) | (v >> 54)) & MASK
        v = a16 ^ d1
        b8 = ((v << 45) | (v >> 19)) & MASK
        v = a21 ^ d1
        b24 = ((v << 2) | (v >> 62)) & MASK
        v = a2 ^ d2
        b20 = ((v << 62) | (v >> 2)) & MASK
        v = a7 ^ d2
        b11 = ((v << 6) | (v >> 58)) & MASK
        v = a12 ^ d2
        b2 = ((v << 43) | (v >> 21)) & MASK
        v = a17 ^ d2
        b18 = ((v << 15) | (v >> 49)) & MASK
        v = a22 ^ d2
        b9 = ((v << 61) | (v >> 3)) & MASK
        v = a3 ^ d3
        b5 = ((v << 28) | (v >> 36)) & MASK
        v = a8 ^ d3
        b21 = ((v << 55) | (v >> 9)) & MASK
        v = a13 ^ d3
        b12 = ((v << 25) | (v >> 39)) & MASK
        v = a18 ^ d3
        b3 = ((v << 21) | (v >> 43)) & MASK
        v = a23 ^ d3
        b19 = ((v << 56) | (v >> 8)) & MASK
        v = a4 ^ d4
        b15 = ((v << 27) | (v >> 37)) & MASK
        v = a9 ^ d4
        b6 = ((v << 20) | (v >> 44)) & MASK
        v = a14 ^ d4
        b22 = ((v << 39) | (v >> 25)) & MASK
        v = a19 ^ d4
        b13 = ((v << 8) | (v >> 56)) & MASK
        v = a24 ^ d4
        b4 = ((v << 14) | (v >> 50)) & MASK
        a0 = b0 ^ (~b1 & b2)
        a1 = b1 ^ (~b2 & b3)
        a2 = b2 ^ (~b3 & b4)
        a3 = b3 ^ (~b4 & b0)
        a4 = b4 ^ (~b0 & b1)
        a5 = b5 ^ (~b6 & b7)
        a6 = b6 ^ (~b7 & b8)
        a7 = b7 ^ (~b8 & b9)
        a8 = b8 ^ (~b9 & b5)
        a9 = b9 ^ (~b5 & b6)
        a10 = b10 ^ (~b11 & b12)
        a11 = b11 ^ (~b12 & b13)
        a12 = b12 ^ (~b13 & b14)
        a13 = b13 ^ (~b14 & b10)
        a14 = b14 ^ (~b10 & b11)
        a15 = b15 ^ (~b16 & b17)
        a16 = b16 ^ (~b17 & b18)
        a17 = b17 ^ (~b18 & b19)
        a18 = b18 ^ (~b19 & b15)
        a19 = b19 ^ (~b15 & b16)
        a20 = b20 ^ (~b21 & b22)
        a21 = b21 ^ (~b22 & b23)
        a22 = b22 ^ (~b23 & b24)
        a23 = b23 ^ (~b24 & b20)
        a24 = b24 ^ (~b20 & b21)
        a0 ^= rc
    return [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24]


def _absorb(state, block):
    lanes = struct.unpack("<17Q", block)
    for i in range(17):
        state[i] ^= lanes[i]
    state[:] = keccak_f(state)


class SHA3_256:
    digest_size = 32
    block_size = RATE

    def __init__(self, data=b""):
        self._state = [0] * STATE_LANES
        self._buffer = b""
        if data:
            self.update(data)

    def update(self, message):
        data = self._buffer + message
        full = len(data) - len(data) % RATE
        for offset in range(0, full, RATE):
            _absorb(self._state, data[offset:offset + RATE])
        self._buffer = data[full:]

    def digest(self):
        state = list(self._state)
        # суффикс SHA-3 (биты 01) и дополнение pad10*1
        last = bytearray(self._buffer) + b"\x06" + b"\x00" * (RATE - len(self._buffer) - 1)
        last[-1] |= 0x80
        _absorb(state, bytes(last))
        return struct.pack("<4Q", *state[:4])

    def hexdigest(self):
        return self.digest().hex()

    def hash(self, message):
        self.update(message)
        return self.hexdigest()
