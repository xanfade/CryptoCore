from cryptocore.modes.common import BLOCK_SIZE, aes_primitive, check_iv, xor_bytes

COUNTER_MODULUS = 1 << (BLOCK_SIZE * 8)


def encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    primitive = aes_primitive(key)

    counter = int.from_bytes(iv, "big")
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        keystream_block = primitive.encrypt(counter.to_bytes(BLOCK_SIZE, "big"))
        ciphertext += xor_bytes(block, keystream_block)
        counter = (counter + 1) % COUNTER_MODULUS

    return bytes(ciphertext)


# в CTR расшифрование совпадает с шифрованием
decrypt = encrypt
