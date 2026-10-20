import secrets

from cryptocore.aead.base import AEAD, AUTH_FAILED_MESSAGE, AuthenticationError, iter_chunks
from cryptocore.aead.kdf import hkdf_sha256
from cryptocore.csprng import generate_random_bytes
from cryptocore.mac.hmac import HMAC
from cryptocore.modes import cbc, cfb, ctr, ofb

MODES = {"ctr": ctr, "cbc": cbc, "cfb": cfb, "ofb": ofb}
IV_LENGTH = 16
ENC_KEY_LENGTH = 16
MAC_KEY_LENGTH = 32
TAG_LENGTH = 32


class EncryptThenMAC(AEAD):
    """C = E(K_e, P), T = HMAC(K_m, C || AAD || len(AAD)), результат = C || T.

    C включает IV, поэтому IV тоже защищён тегом. Длина AAD добавляется в конец, чтобы граница между C и AAD
    была однозначной. Ключи шифрования и MAC получаются из мастер-ключа через HKDF с разными метками.
    """

    def __init__(self, master_key, mode="ctr"):
        if mode not in MODES:
            raise ValueError(f"неподдерживаемый режим шифрования: {mode}")
        master_key = bytes(master_key)
        if not master_key:
            raise ValueError("мастер-ключ не может быть пустым")
        self.mode = mode
        label = mode.encode("ascii")
        self.enc_key = hkdf_sha256(master_key, b"cryptocore-etm|enc|" + label, ENC_KEY_LENGTH)
        self.mac_key = hkdf_sha256(master_key, b"cryptocore-etm|mac|" + label, MAC_KEY_LENGTH)

    def _tag(self, ciphertext: bytes, aad) -> bytes:
        mac = HMAC(self.mac_key, "sha256")
        mac.update(ciphertext)
        aad_length = 0
        for chunk in iter_chunks(aad):
            mac.update(chunk)
            aad_length += len(chunk)
        mac.update(aad_length.to_bytes(8, "big"))
        return mac.digest()

    def encrypt(self, plaintext, aad=b""):
        iv = generate_random_bytes(IV_LENGTH)
        ciphertext = iv + MODES[self.mode].encrypt(self.enc_key, bytes(plaintext), iv)
        return ciphertext + self._tag(ciphertext, aad)

    def decrypt(self, data, aad=b""):
        data = bytes(data)
        if len(data) < IV_LENGTH + TAG_LENGTH:
            raise AuthenticationError("Authentication failed: input is too short")
        ciphertext, tag = data[:-TAG_LENGTH], data[-TAG_LENGTH:]
        # тег проверяется до расшифрования (и до снятия дополнения в CBC)
        if not secrets.compare_digest(self._tag(ciphertext, aad), tag):
            raise AuthenticationError(AUTH_FAILED_MESSAGE)
        return MODES[self.mode].decrypt(self.enc_key, ciphertext[IV_LENGTH:], ciphertext[:IV_LENGTH])
