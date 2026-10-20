from cryptocore.modes.common import BLOCK_SIZE, aes_primitive, check_iv, xor_bytes


def encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    primitive = aes_primitive(key)

    register = iv
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        encrypted_block = xor_bytes(block, primitive.encrypt(register))
        ciphertext += encrypted_block
        register = encrypted_block

    return bytes(ciphertext)


def decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    primitive = aes_primitive(key)

    register = iv
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        plaintext += xor_bytes(block, primitive.encrypt(register))
        register = block

    return bytes(plaintext)
