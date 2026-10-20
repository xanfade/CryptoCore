import hashlib
import hmac as std_hmac
import os

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from cryptocore.dgst import feed_stream
from cryptocore.mac.cmac import AESCMAC
from cryptocore.mac.hmac import HMAC

LARGE = os.environ.get("CRYPTOCORE_LARGE_TEST") == "1"
SIZE = 1_100_000_000  # больше 1 ГБ

pytestmark = pytest.mark.skipif(not LARGE, reason="долгий тест: задайте CRYPTOCORE_LARGE_TEST=1")

HMAC_KEY = os.urandom(100)
CMAC_KEY = os.urandom(16)


def write_large_file(path, reference):
    block = os.urandom(1_000_000)
    written = 0
    with open(path, "wb") as f:
        while written < SIZE:
            size = min(len(block), SIZE - written)
            f.write(block[:size])
            reference.update(block[:size])
            written += size


def test_hmac_of_file_larger_than_one_gigabyte(tmp_path):
    reference = std_hmac.new(HMAC_KEY, digestmod=hashlib.sha256)
    path = tmp_path / "large.bin"
    write_large_file(path, reference)

    mac = HMAC(HMAC_KEY, "sha256")
    with open(path, "rb") as f:
        feed_stream(f, mac)
    assert mac.hexdigest() == reference.hexdigest()


def test_cmac_of_file_larger_than_one_gigabyte(tmp_path):
    reference = ReferenceCMAC.new(CMAC_KEY, ciphermod=AES)
    path = tmp_path / "large.bin"
    write_large_file(path, reference)

    mac = AESCMAC(CMAC_KEY)
    with open(path, "rb") as f:
        feed_stream(f, mac)
    assert mac.hexdigest() == reference.hexdigest()
