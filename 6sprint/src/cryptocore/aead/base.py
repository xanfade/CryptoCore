from abc import ABC, abstractmethod


class AuthenticationError(Exception):
    pass


AUTH_FAILED_MESSAGE = "Authentication failed: AAD mismatch or ciphertext tampered"


class AEAD(ABC):
    @abstractmethod
    def encrypt(self, plaintext, aad=b""):
        """Возвращает шифртекст вместе со всем, что нужно для проверки (тег, nonce)."""

    @abstractmethod
    def decrypt(self, data, aad=b""):
        """Проверяет тег и только потом возвращает открытый текст; при ошибке бросает AuthenticationError."""


def iter_chunks(data, chunk_size=65536):
    """Приводит bytes, файловый объект или итерируемое из кусков к последовательности кусков bytes."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        yield bytes(data)
        return
    if hasattr(data, "read"):
        while True:
            chunk = data.read(chunk_size)
            if not chunk:
                return
            yield bytes(chunk)
    for chunk in data:
        yield bytes(chunk)
