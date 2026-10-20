import secrets

from cryptocore.aead.base import AEAD, AuthenticationError, iter_chunks
from cryptocore.csprng import generate_random_bytes
from cryptocore.modes.common import BLOCK_SIZE, aes_primitive

NONCE_LENGTH = 12
TAG_LENGTH = 16
MAX_PLAINTEXT_BYTES = (1 << 36) - 32  # 2^39 - 256 бит по NIST SP 800-38D

_R = 0xE1000000000000000000000000000000
_MASK_128 = (1 << 128) - 1
_MASK_32 = 0xFFFFFFFF


def gf_mult(x: int, y: int) -> int:
    """Умножение в GF(2^128) по модулю x^128 + x^7 + x^2 + x + 1 (алгоритм 1 из NIST SP 800-38D)."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _build_tables(h: int):
    # умножение на H линейно, поэтому X * H = XOR по байтам X значений из таблиц 16 x 256
    tables = []
    for position in range(16):
        shift = 8 * (15 - position)
        basis = [gf_mult(1 << (shift + bit), h) for bit in range(8)]
        table = [0] * 256
        for value in range(1, 256):
            lowest = (value & -value).bit_length() - 1
            table[value] = table[value & (value - 1)] ^ basis[lowest]
        tables.append(table)
    return tables


class _GHash:
    def __init__(self, tables):
        (self._t0, self._t1, self._t2, self._t3, self._t4, self._t5, self._t6, self._t7,
         self._t8, self._t9, self._t10, self._t11, self._t12, self._t13, self._t14, self._t15) = tables
        self._y = 0
        self._buffer = b""
        self._aad_length = 0
        self._ciphertext_length = 0

    def _absorb_block(self, block: bytes) -> None:
        v = (self._y ^ int.from_bytes(block, "big")).to_bytes(16, "big")
        self._y = (
            self._t0[v[0]] ^ self._t1[v[1]] ^ self._t2[v[2]] ^ self._t3[v[3]]
            ^ self._t4[v[4]] ^ self._t5[v[5]] ^ self._t6[v[6]] ^ self._t7[v[7]]
            ^ self._t8[v[8]] ^ self._t9[v[9]] ^ self._t10[v[10]] ^ self._t11[v[11]]
            ^ self._t12[v[12]] ^ self._t13[v[13]] ^ self._t14[v[14]] ^ self._t15[v[15]]
        )

    def update(self, data: bytes) -> None:
        data = self._buffer + data
        full = len(data) - len(data) % BLOCK_SIZE
        for offset in range(0, full, BLOCK_SIZE):
            self._absorb_block(data[offset:offset + BLOCK_SIZE])
        self._buffer = data[full:]

    def pad(self) -> None:
        # дополнение нулями до границы блока между частями AAD и шифртекста
        if self._buffer:
            self._absorb_block(self._buffer + bytes(BLOCK_SIZE - len(self._buffer)))
            self._buffer = b""

    def update_aad(self, data: bytes) -> None:
        self._aad_length += len(data)
        self.update(data)

    def update_ciphertext(self, data: bytes) -> None:
        self._ciphertext_length += len(data)
        self.update(data)

    def digest(self) -> bytes:
        self.pad()
        lengths = ((self._aad_length * 8) << 64) | (self._ciphertext_length * 8)
        self._absorb_block(lengths.to_bytes(16, "big"))
        return self._y.to_bytes(16, "big")


class GCM(AEAD):
    def __init__(self, key, nonce=None):
        key = bytes(key)
        self._cipher = aes_primitive(key)
        self._explicit_nonce = nonce is not None
        if nonce is not None:
            nonce = bytes(nonce)
            if len(nonce) == 0:
                raise ValueError("nonce не может быть пустым")
        self.nonce = nonce if nonce is not None else generate_random_bytes(NONCE_LENGTH)

        h = int.from_bytes(self._cipher.encrypt(bytes(BLOCK_SIZE)), "big")
        self._tables = _build_tables(h)
        self._h = h

    def _new_ghash(self) -> _GHash:
        return _GHash(self._tables)

    def _initial_counter(self, nonce: bytes) -> bytes:
        if len(nonce) == NONCE_LENGTH:
            return nonce + b"\x00\x00\x00\x01"
        # для nonce другой длины J0 = GHASH(nonce, 0, len(nonce))
        ghash = self._new_ghash()
        ghash.update(nonce)
        ghash.pad()
        ghash._absorb_block((len(nonce) * 8).to_bytes(16, "big"))
        return ghash._y.to_bytes(16, "big")

    def _gctr(self, j0: bytes, data: bytes) -> bytes:
        # шифрование в режиме CTR со счётчиком inc32, начиная с J0 + 1
        prefix = j0[:12]
        counter = int.from_bytes(j0[12:], "big")
        output = bytearray()
        encrypt_block = self._cipher.encrypt
        for offset in range(0, len(data), BLOCK_SIZE):
            counter = (counter + 1) & _MASK_32
            keystream = encrypt_block(prefix + counter.to_bytes(4, "big"))
            block = data[offset:offset + BLOCK_SIZE]
            output += (int.from_bytes(block, "big") ^
                       (int.from_bytes(keystream, "big") >> (8 * (BLOCK_SIZE - len(block))))
                       ).to_bytes(len(block), "big")
        return bytes(output)

    def _tag(self, j0: bytes, aad, ciphertext_chunks) -> bytes:
        ghash = self._new_ghash()
        for chunk in iter_chunks(aad):
            ghash.update_aad(chunk)
        ghash.pad()
        for chunk in ciphertext_chunks:
            ghash.update_ciphertext(chunk)
        s = int.from_bytes(ghash.digest(), "big")
        return (s ^ int.from_bytes(self._cipher.encrypt(j0), "big")).to_bytes(TAG_LENGTH, "big")

    def encrypt_detached(self, plaintext, aad=b"", nonce=None):
        plaintext = bytes(plaintext)
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise ValueError("открытый текст слишком длинный для GCM")
        if nonce is None:
            if self._explicit_nonce:
                nonce = self.nonce
            else:
                nonce = generate_random_bytes(NONCE_LENGTH)
        nonce = bytes(nonce)
        if len(nonce) == 0:
            raise ValueError("nonce не может быть пустым")
        self.nonce = nonce

        j0 = self._initial_counter(nonce)
        ciphertext = self._gctr(j0, plaintext)
        tag = self._tag(j0, aad, [ciphertext])
        return nonce, ciphertext, tag

    def decrypt_detached(self, nonce, ciphertext, tag, aad=b""):
        nonce, ciphertext, tag = bytes(nonce), bytes(ciphertext), bytes(tag)
        if len(nonce) == 0:
            raise ValueError("nonce не может быть пустым")
        if len(tag) != TAG_LENGTH:
            raise AuthenticationError("Authentication failed: invalid tag length")

        j0 = self._initial_counter(nonce)
        expected = self._tag(j0, aad, [ciphertext])
        # тег проверяется до расшифрования: при несовпадении открытый текст не вычисляется вообще
        if not secrets.compare_digest(expected, tag):
            raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")
        return self._gctr(j0, ciphertext)

    def encrypt(self, plaintext, aad=b""):
        nonce, ciphertext, tag = self.encrypt_detached(plaintext, aad)
        return nonce + ciphertext + tag

    def decrypt(self, data, aad=b""):
        nonce_length = len(self.nonce) if self._explicit_nonce else NONCE_LENGTH
        data = bytes(data)
        if len(data) < nonce_length + TAG_LENGTH:
            raise AuthenticationError("Authentication failed: input is too short")
        nonce = data[:nonce_length]
        ciphertext = data[nonce_length:-TAG_LENGTH]
        tag = data[-TAG_LENGTH:]
        return self.decrypt_detached(nonce, ciphertext, tag, aad)
