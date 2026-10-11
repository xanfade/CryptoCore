from Crypto.Cipher import AES

BLOCK_SIZE = 16


def aes_primitive(key: bytes):
    # MODE_ECB без цепочек: один вызов = одно "сырое" преобразование блока AES
    return AES.new(key, AES.MODE_ECB)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV должен быть длиной {BLOCK_SIZE} байт")
