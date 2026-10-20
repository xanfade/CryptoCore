from cryptocore.mac.hmac import HMAC

HASH_LENGTH = 32


def hkdf_sha256(key_material: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    # HKDF по RFC 5869 поверх собственного HMAC-SHA256
    if length < 0 or length > 255 * HASH_LENGTH:
        raise ValueError("недопустимая длина выходных данных HKDF")
    if not salt:
        salt = bytes(HASH_LENGTH)

    pseudo_random_key = bytes.fromhex(HMAC(salt, "sha256").compute(key_material))

    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        mac = HMAC(pseudo_random_key, "sha256")
        mac.update(block + info + bytes([counter]))
        block = mac.digest()
        output += block
        counter += 1
    return output[:length]
