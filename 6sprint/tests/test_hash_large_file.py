import hashlib
import os

import pytest

from cryptocore.dgst import hash_stream

LARGE = os.environ.get("CRYPTOCORE_LARGE_TEST") == "1"
SIZE = 1_100_000_000  # больше 1 ГБ

pytestmark = pytest.mark.skipif(not LARGE, reason="долгий тест: задайте CRYPTOCORE_LARGE_TEST=1")


@pytest.mark.parametrize("algorithm,reference", [
    ("sha256", hashlib.sha256),
    ("sha3-256", hashlib.sha3_256),
])
def test_file_larger_than_one_gigabyte(algorithm, reference, tmp_path):
    block = os.urandom(1_000_000)
    path = tmp_path / "large.bin"
    expected = reference()
    written = 0
    with open(path, "wb") as f:
        while written < SIZE:
            size = min(len(block), SIZE - written)
            f.write(block[:size])
            expected.update(block[:size])
            written += size

    with open(path, "rb") as f:
        assert hash_stream(f, algorithm) == expected.hexdigest()
