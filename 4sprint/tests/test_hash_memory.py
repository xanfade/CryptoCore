import pytest

from cryptocore.dgst import CHUNK_SIZE, hash_stream
from cryptocore.hash import ALGORITHMS


class RecordingStream:
    def __init__(self, total):
        self.remaining = total
        self.requested_sizes = []

    def read(self, n):
        self.requested_sizes.append(n)
        size = min(n, self.remaining)
        self.remaining -= size
        return b"\xa5" * size


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_input_is_read_only_in_fixed_size_chunks(algorithm):
    stream = RecordingStream(100_000)
    hash_stream(stream, algorithm)
    assert set(stream.requested_sizes) == {CHUNK_SIZE}
    assert len(stream.requested_sizes) > 100_000 // CHUNK_SIZE


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_hasher_state_does_not_grow_with_input(algorithm):
    hasher = ALGORITHMS[algorithm]()
    for _ in range(40):
        hasher.update(b"\x5a" * CHUNK_SIZE)
        assert len(hasher._buffer) < hasher.block_size


def test_chunk_size_is_reasonable():
    assert CHUNK_SIZE in (4096, 8192)
