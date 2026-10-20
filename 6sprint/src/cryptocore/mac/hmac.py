from cryptocore.hash import ALGORITHMS

IPAD_BYTE = 0x36
OPAD_BYTE = 0x5C


class HMAC:
    def __init__(self, key, hash_function="sha256"):
        if hash_function not in ALGORITHMS:
            raise ValueError(f"неизвестная хеш-функция: {hash_function}")
        self._hash_class = ALGORITHMS[hash_function]
        self.block_size = self._hash_class.block_size
        self.key = self._process_key(bytes(key))

        self._ipad = self._xor_bytes(self.key, bytes([IPAD_BYTE]) * self.block_size)
        self._opad = self._xor_bytes(self.key, bytes([OPAD_BYTE]) * self.block_size)
        self._inner = self._hash_class(self._ipad)

    def _process_key(self, key):
        # ключ длиннее блока сначала хешируется, короче блока дополняется нулями
        if len(key) > self.block_size:
            key = self._hash_class(key).digest()
        if len(key) < self.block_size:
            key = key + b"\x00" * (self.block_size - len(key))
        return key

    @staticmethod
    def _xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def update(self, message):
        self._inner.update(message)

    def digest(self):
        inner_hash = self._inner.digest()
        return self._hash_class(self._opad + inner_hash).digest()

    def hexdigest(self):
        return self.digest().hex()

    def compute(self, message):
        # HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m)), не меняя состояние объекта
        inner = self._hash_class(self._ipad)
        inner.update(message)
        return self._hash_class(self._opad + inner.digest()).hexdigest()
