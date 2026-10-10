from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Длина дополненных данных должна быть ненулевым кратным размеру блока")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Некорректное дополнение PKCS#7")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Некорректное дополнение PKCS#7")

    return data[:-pad_len]


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)

    primitive = AES.new(key, AES.MODE_ECB)
    ciphertext = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        ciphertext += primitive.encrypt(block)

    return bytes(ciphertext)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста должна быть ненулевым кратным размеру блока")

    primitive = AES.new(key, AES.MODE_ECB)
    padded = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        padded += primitive.decrypt(block)

    return pkcs7_unpad(bytes(padded), BLOCK_SIZE)
