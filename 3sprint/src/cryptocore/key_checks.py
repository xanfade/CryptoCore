def weak_key_reason(key: bytes):
    if len(key) < 2:
        return None

    if len(set(key)) == 1:
        if key[0] == 0:
            return "ключ состоит только из нулевых байтов"
        return f"все байты ключа одинаковы (0x{key[0]:02x})"

    if all(key[i] == (key[i - 1] + 1) % 256 for i in range(1, len(key))):
        return "байты ключа идут по возрастанию подряд"

    if all(key[i] == (key[i - 1] - 1) % 256 for i in range(1, len(key))):
        return "байты ключа идут по убыванию подряд"

    return None
