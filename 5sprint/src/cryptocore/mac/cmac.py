from cryptocore.modes.common import BLOCK_SIZE, aes_primitive

KEY_LENGTH = 16
_RB = 0x87
_MASK_128 = (1 << 128) - 1


def _xor_block(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(BLOCK_SIZE, "big")


def _double(block: bytes) -> bytes:
    value = int.from_bytes(block, "big")
    shifted = (value << 1) & _MASK_128
    if value >> 127:
        shifted ^= _RB
    return shifted.to_bytes(BLOCK_SIZE, "big")


class AESCMAC:
    digest_size = BLOCK_SIZE

    def __init__(self, key):
        key = bytes(key)
        if len(key) != KEY_LENGTH:
            raise ValueError(f"ключ AES-CMAC должен быть длиной {KEY_LENGTH} байт, получено {len(key)}")
        self._cipher = aes_primitive(key)

        l_value = self._cipher.encrypt(bytes(BLOCK_SIZE))
        self._k1 = _double(l_value)
        self._k2 = _double(self._k1)

        self._state = bytes(BLOCK_SIZE)
        self._buffer = b""

    def update(self, message):
        data = self._buffer + message
        if len(data) <= BLOCK_SIZE:
            self._buffer = data
            return

        # последний блок (1..16 байт) всегда остаётся в буфере до вызова digest()
        process = ((len(data) - 1) // BLOCK_SIZE) * BLOCK_SIZE
        state = self._state
        for offset in range(0, process, BLOCK_SIZE):
            state = self._cipher.encrypt(_xor_block(state, data[offset:offset + BLOCK_SIZE]))
        self._state = state
        self._buffer = data[process:]

    def digest(self):
        if len(self._buffer) == BLOCK_SIZE:
            last = _xor_block(self._buffer, self._k1)
        else:
            padded = self._buffer + b"\x80" + b"\x00" * (BLOCK_SIZE - len(self._buffer) - 1)
            last = _xor_block(padded, self._k2)
        return self._cipher.encrypt(_xor_block(self._state, last))

    def hexdigest(self):
        return self.digest().hex()

    def compute(self, message):
        mac = AESCMAC.__new__(AESCMAC)
        mac.__dict__.update(self.__dict__)
        mac.update(message)
        return mac.hexdigest()
