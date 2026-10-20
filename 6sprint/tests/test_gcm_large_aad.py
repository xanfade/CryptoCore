import os

import pytest
from Crypto.Cipher import AES

from cryptocore.aead import EncryptThenMAC
from cryptocore.modes.gcm import GCM

LARGE = os.environ.get("CRYPTOCORE_LARGE_TEST") == "1"
CHUNK_SIZE = 1_000_000
CHUNKS = 1100  # 1,1 ГБ AAD для GCM
ETM_CHUNKS = 50  # 50 МБ AAD для Encrypt-then-MAC (собственный HMAC работает около 0,45 МБ/с)

pytestmark = pytest.mark.skipif(not LARGE, reason="долгий тест: задайте CRYPTOCORE_LARGE_TEST=1")

CHUNK = os.urandom(CHUNK_SIZE)


def aad_stream(chunks=CHUNKS):
    for _ in range(chunks):
        yield CHUNK


def test_gcm_with_aad_larger_than_one_gigabyte():
    key, nonce = os.urandom(16), os.urandom(12)

    reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
    for chunk in aad_stream():
        reference.update(chunk)
    expected_ciphertext, expected_tag = reference.encrypt_and_digest(b"payload")

    _, ciphertext, tag = GCM(key, nonce).encrypt_detached(b"payload", aad=aad_stream())
    assert (ciphertext, tag) == (expected_ciphertext, expected_tag)

    assert GCM(key, nonce).decrypt_detached(nonce, ciphertext, tag, aad=aad_stream()) == b"payload"


def test_encrypt_then_mac_with_large_aad_in_chunks():
    etm = EncryptThenMAC(os.urandom(16), "ctr")
    data = etm.encrypt(b"payload", aad_stream(ETM_CHUNKS))
    assert etm.decrypt(data, aad_stream(ETM_CHUNKS)) == b"payload"
