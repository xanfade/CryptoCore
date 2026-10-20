from cryptocore.modes.common import BLOCK_SIZE, aes_primitive, check_iv, xor_bytes
from cryptocore.modes.ecb import pkcs7_pad, pkcs7_unpad


def encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    primitive = aes_primitive(key)

    previous = iv
    ciphertext = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        previous = primitive.encrypt(xor_bytes(block, previous))
        ciphertext += previous

    return bytes(ciphertext)


def decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста должна быть ненулевым кратным размеру блока")
    primitive = aes_primitive(key)

    previous = iv
    padded = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        padded += xor_bytes(primitive.decrypt(block), previous)
        previous = block

    return pkcs7_unpad(bytes(padded), BLOCK_SIZE)
