from cryptocore.modes.common import BLOCK_SIZE, aes_primitive, check_iv, xor_bytes


def encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    primitive = aes_primitive(key)

    keystream_block = iv
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        keystream_block = primitive.encrypt(keystream_block)
        ciphertext += xor_bytes(block, keystream_block)

    return bytes(ciphertext)


# в OFB гамма не зависит от данных, поэтому расшифрование совпадает с шифрованием
decrypt = encrypt
