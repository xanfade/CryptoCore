import pytest
from Crypto.Cipher import AES

from cryptocore.modes import ecb


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_pkcs7_pad_adds_full_block_when_already_aligned():
    data = bytes(16)
    padded = ecb.pkcs7_pad(data)
    assert len(padded) == 32
    assert padded[16:] == bytes([16]) * 16


def test_pkcs7_pad_pads_to_next_block_boundary():
    data = bytes(5)
    padded = ecb.pkcs7_pad(data)
    assert len(padded) == 16
    assert padded[5:] == bytes([11]) * 11


def test_pkcs7_pad_unpad_roundtrip_various_lengths():
    for length in range(0, 40):
        data = bytes([i % 256 for i in range(length)])
        padded = ecb.pkcs7_pad(data)
        assert len(padded) % ecb.BLOCK_SIZE == 0
        assert ecb.pkcs7_unpad(padded) == data


def test_pkcs7_unpad_rejects_bad_padding_byte():
    bad = bytes(15) + bytes([0])
    with pytest.raises(ValueError):
        ecb.pkcs7_unpad(bad)


def test_pkcs7_unpad_rejects_inconsistent_padding():
    bad = bytes(13) + bytes([0xFF, 3, 3])
    with pytest.raises(ValueError):
        ecb.pkcs7_unpad(bad)


def test_pkcs7_unpad_rejects_wrong_length():
    with pytest.raises(ValueError):
        ecb.pkcs7_unpad(bytes(10))


def test_encrypt_decrypt_roundtrip():
    plaintext = b"The quick brown fox jumps over the lazy dog!"
    ciphertext = ecb.encrypt(KEY, plaintext)
    assert len(ciphertext) % ecb.BLOCK_SIZE == 0
    assert ecb.decrypt(KEY, ciphertext) == plaintext


def test_encrypt_decrypt_roundtrip_empty_plaintext():
    ciphertext = ecb.encrypt(KEY, b"")
    assert len(ciphertext) == ecb.BLOCK_SIZE
    assert ecb.decrypt(KEY, ciphertext) == b""


def test_encrypt_decrypt_roundtrip_binary_data():
    plaintext = bytes(range(256)) * 3
    ciphertext = ecb.encrypt(KEY, plaintext)
    assert ecb.decrypt(KEY, ciphertext) == plaintext


def test_ecb_output_matches_reference_ecb_over_full_buffer():
    plaintext = b"cross-check this ciphertext against the reference implementation"
    padded = ecb.pkcs7_pad(plaintext)
    reference = AES.new(KEY, AES.MODE_ECB).encrypt(padded)
    assert ecb.encrypt(KEY, plaintext) == reference


def test_first_block_matches_fips197_known_answer_vector():
    plaintext_block = bytes.fromhex("00112233445566778899aabbccddeeff")[:16]
    expected_ciphertext_block = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    ciphertext = ecb.encrypt(KEY, plaintext_block)
    assert ciphertext[:16] == expected_ciphertext_block


def test_decrypt_rejects_ciphertext_not_multiple_of_block_size():
    with pytest.raises(ValueError):
        ecb.decrypt(KEY, bytes(10))


def test_decrypt_rejects_empty_ciphertext():
    with pytest.raises(ValueError):
        ecb.decrypt(KEY, b"")
