import io
import os

import pytest
from Crypto.Cipher import AES

from cryptocore.aead import AuthenticationError
from cryptocore.modes import gcm as gcm_module
from cryptocore.modes.gcm import GCM, gf_mult

# Тестовые случаи 1-4 из оригинальной спецификации GCM (McGrew, Viega), включённые в NIST SP 800-38D
KEY3 = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
IV3 = bytes.fromhex("cafebabefacedbaddecaf888")
PT3 = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
AAD4 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")

KATS = [
    ("tc1", bytes(16), bytes(12), b"", b"", b"", "58e2fccefa7e3061367f1d57a4e7455a"),
    ("tc2", bytes(16), bytes(12), bytes(16), b"", bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"),
     "ab6e47d42cec13bdf53a67b21257bddf"),
    ("tc3", KEY3, IV3, PT3, b"",
     bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                   "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
    ("tc4", KEY3, IV3, PT3[:60], AAD4,
     bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                   "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"),
     "5bc94fbc3221a5db94fae95ae7121a47"),
]


@pytest.mark.parametrize("name,key,nonce,plaintext,aad,ciphertext,tag", KATS, ids=[k[0] for k in KATS])
def test_known_answer_vectors(name, key, nonce, plaintext, aad, ciphertext, tag):
    _, got_ciphertext, got_tag = GCM(key, nonce).encrypt_detached(plaintext, aad)
    assert got_ciphertext == ciphertext
    assert got_tag.hex() == tag
    assert GCM(key, nonce).decrypt_detached(nonce, ciphertext, bytes.fromhex(tag), aad) == plaintext


def test_gf_mult_basic_properties():
    one = 1 << 127  # элемент "1" в представлении GCM
    for _ in range(20):
        x, y, z = (int.from_bytes(os.urandom(16), "big") for _ in range(3))
        assert gf_mult(x, one) == x
        assert gf_mult(x, y) == gf_mult(y, x)
        assert gf_mult(x, y ^ z) == gf_mult(x, y) ^ gf_mult(x, z)
        assert gf_mult(x, 0) == 0


def test_table_multiplication_matches_bitwise_algorithm():
    h = int.from_bytes(os.urandom(16), "big")
    tables = gcm_module._build_tables(h)
    ghash = gcm_module._GHash(tables)
    for _ in range(20):
        block = os.urandom(16)
        ghash._y = int.from_bytes(os.urandom(16), "big")
        before = ghash._y
        ghash._absorb_block(block)
        assert ghash._y == gf_mult(before ^ int.from_bytes(block, "big"), h)


@pytest.mark.parametrize("nonce_length", [1, 8, 12, 16, 60])
@pytest.mark.parametrize("aad_length", [0, 1, 15, 16, 17, 40, 100])
@pytest.mark.parametrize("plaintext_length", [0, 1, 15, 16, 17, 31, 33, 100, 257])
def test_matches_pycryptodome(nonce_length, aad_length, plaintext_length):
    key = os.urandom(16)
    nonce, aad, plaintext = os.urandom(nonce_length), os.urandom(aad_length), os.urandom(plaintext_length)
    reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
    reference.update(aad)
    expected_ciphertext, expected_tag = reference.encrypt_and_digest(plaintext)

    _, ciphertext, tag = GCM(key, nonce).encrypt_detached(plaintext, aad)

    assert (ciphertext, tag) == (expected_ciphertext, expected_tag)


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_all_aes_key_sizes(key_length):
    key, nonce, aad, plaintext = os.urandom(key_length), os.urandom(12), b"aad", os.urandom(50)
    reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
    reference.update(aad)
    expected = reference.encrypt_and_digest(plaintext)
    assert GCM(key, nonce).encrypt_detached(plaintext, aad)[1:] == expected


def test_interoperability_with_openssl_backed_library():
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    for plaintext_length, aad_length in [(0, 0), (5, 0), (0, 7), (100, 20), (1000, 333)]:
        key, nonce = os.urandom(16), os.urandom(12)
        plaintext, aad = os.urandom(plaintext_length), os.urandom(aad_length)

        ours = GCM(key, nonce).encrypt(plaintext, aad)
        assert ours[12:] == aead.AESGCM(key).encrypt(nonce, plaintext, aad)

        theirs = nonce + aead.AESGCM(key).encrypt(nonce, plaintext, aad)
        assert GCM(key).decrypt(theirs, aad) == plaintext


def test_output_format_is_nonce_ciphertext_tag():
    gcm = GCM(os.urandom(16))
    plaintext = os.urandom(37)
    data = gcm.encrypt(plaintext, b"aad")
    assert len(data) == 12 + 37 + 16
    assert data[:12] == gcm.nonce


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 100, 1000])
def test_roundtrip(length):
    key, aad = os.urandom(16), os.urandom(11)
    plaintext = os.urandom(length)
    assert GCM(key).decrypt(GCM(key).encrypt(plaintext, aad), aad) == plaintext


def test_empty_aad_and_empty_plaintext():
    key = os.urandom(16)
    gcm = GCM(key)
    assert gcm.decrypt(gcm.encrypt(b"secret"), b"") == b"secret"
    assert gcm.decrypt(gcm.encrypt(b"")) == b""
    assert gcm.encrypt(b"x", b"") != gcm.encrypt(b"x", b"")  # разные nonce


def test_wrong_aad_fails_and_returns_nothing():
    key = os.urandom(16)
    gcm = GCM(key)
    data = gcm.encrypt(b"Secret message", b"correct_aad")
    result = None
    with pytest.raises(AuthenticationError):
        result = GCM(key, gcm.nonce).decrypt(data, b"wrong_aad")
    assert result is None


def test_missing_or_extra_aad_fails():
    key = os.urandom(16)
    data = GCM(key).encrypt(b"message", b"aad")
    with pytest.raises(AuthenticationError):
        GCM(key).decrypt(data, b"")
    with pytest.raises(AuthenticationError):
        GCM(key).decrypt(data, b"aad ")


def test_wrong_key_fails():
    data = GCM(os.urandom(16)).encrypt(b"message", b"aad")
    with pytest.raises(AuthenticationError):
        GCM(os.urandom(16)).decrypt(data, b"aad")


def test_every_single_bit_flip_is_detected():
    key, aad = os.urandom(16), b"associated"
    data = GCM(key).encrypt(b"Another secret message", aad)
    for index in range(len(data)):
        for bit in range(8):
            tampered = bytearray(data)
            tampered[index] ^= 1 << bit
            with pytest.raises(AuthenticationError):
                GCM(key).decrypt(bytes(tampered), aad)


def test_truncated_and_extended_data_fail():
    key = os.urandom(16)
    data = GCM(key).encrypt(b"message", b"aad")
    for tampered in (data[:-1], data + b"\x00", data[1:], b"\x00" + data, b"", data[:27]):
        with pytest.raises(AuthenticationError):
            GCM(key).decrypt(tampered, b"aad")


def test_tag_is_checked_before_any_plaintext_is_computed(monkeypatch):
    key = os.urandom(16)
    gcm = GCM(key)
    data = gcm.encrypt(b"message", b"aad")

    def forbidden(*args, **kwargs):
        raise AssertionError("расшифрование началось до проверки тега")

    monkeypatch.setattr(GCM, "_gctr", forbidden)
    tampered = bytearray(data)
    tampered[14] ^= 1
    with pytest.raises(AuthenticationError):
        GCM(key).decrypt(bytes(tampered), b"aad")


def test_1000_generated_nonces_are_unique():
    key = os.urandom(16)
    nonces = set()
    gcm = GCM(key)
    for _ in range(1000):
        gcm.encrypt(b"x")
        nonces.add(gcm.nonce)
    assert len(nonces) == 1000
    assert all(len(n) == 12 for n in nonces)


def test_nonce_comes_from_csprng_function(monkeypatch):
    monkeypatch.setattr(gcm_module, "generate_random_bytes", lambda n: b"\x5a" * n)
    gcm = GCM(os.urandom(16))
    assert gcm.nonce == b"\x5a" * 12
    assert gcm.encrypt(b"x")[:12] == b"\x5a" * 12


def test_explicit_nonce_is_used_as_is():
    nonce = bytes(range(12))
    gcm = GCM(os.urandom(16), nonce)
    assert gcm.encrypt(b"x")[:12] == nonce


def test_empty_nonce_is_rejected():
    with pytest.raises(ValueError):
        GCM(os.urandom(16), b"")


def test_nonce_of_other_length_roundtrip():
    key = os.urandom(16)
    for length in (1, 8, 16, 20):
        gcm = GCM(key, os.urandom(length))
        assert gcm.decrypt(gcm.encrypt(b"data", b"aad"), b"aad") == b"data"


def test_ciphertext_does_not_contain_plaintext_and_differs_per_nonce():
    key = os.urandom(16)
    plaintext = b"A" * 64
    assert plaintext not in GCM(key).encrypt(plaintext)
    assert GCM(key, bytes(12)).encrypt(plaintext) != GCM(key, b"\x01" * 12).encrypt(plaintext)


def test_large_aad_is_processed_in_chunks_without_holding_it_in_memory():
    key, nonce = os.urandom(16), os.urandom(12)
    chunk = os.urandom(65536)
    total_chunks = 48  # 3 МБ AAD

    def stream():
        for _ in range(total_chunks):
            yield chunk

    reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
    for _ in range(total_chunks):
        reference.update(chunk)
    _, expected_tag = reference.encrypt_and_digest(b"payload")

    _, ciphertext, tag = GCM(key, nonce).encrypt_detached(b"payload", aad=stream())
    assert tag == expected_tag
    assert GCM(key, nonce).decrypt_detached(nonce, ciphertext, tag, aad=stream()) == b"payload"


@pytest.mark.parametrize("chunk_size", [1, 7, 15, 16, 17, 100, 5000])
def test_aad_chunking_does_not_change_result(chunk_size):
    key, nonce, aad = os.urandom(16), os.urandom(12), os.urandom(1234)
    expected = GCM(key, nonce).encrypt_detached(b"data", aad)
    chunks = [aad[i:i + chunk_size] for i in range(0, len(aad), chunk_size)]
    assert GCM(key, nonce).encrypt_detached(b"data", chunks) == expected
    assert GCM(key, nonce).encrypt_detached(b"data", io.BytesIO(aad)) == expected


def test_aad_boundary_between_aad_and_ciphertext_is_unambiguous():
    key, nonce = os.urandom(16), os.urandom(12)
    _, ct1, tag1 = GCM(key, nonce).encrypt_detached(b"", aad=b"AAAA")
    _, ct2, tag2 = GCM(key, nonce).encrypt_detached(b"AAAA", aad=b"")
    assert tag1 != tag2


def test_plaintext_too_long_is_rejected(monkeypatch):
    monkeypatch.setattr(gcm_module, "MAX_PLAINTEXT_BYTES", 10)
    with pytest.raises(ValueError):
        GCM(os.urandom(16)).encrypt(b"x" * 11)
