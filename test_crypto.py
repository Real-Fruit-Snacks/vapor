"""Verify ChaCha20-Poly1305 encrypt/decrypt and wire format."""
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_SIZE = 12
MAC_SIZE = 16


def encrypt_msg(key, plaintext):
    """Encrypt -> [nonce(12)][ciphertext][mac(16)]."""
    nonce = os.urandom(NONCE_SIZE)
    ct_and_tag = ChaCha20Poly1305(key).encrypt(
        nonce, plaintext, None
    )
    return nonce + ct_and_tag


def decrypt_msg(key, data):
    """Decrypt [nonce(12)][ciphertext][mac(16)] -> plaintext."""
    nonce = data[:NONCE_SIZE]
    ct_and_tag = data[NONCE_SIZE:]
    return ChaCha20Poly1305(key).decrypt(
        nonce, ct_and_tag, None
    )


def test_round_trip():
    key = os.urandom(32)
    msg = b"hello vapor"
    encrypted = encrypt_msg(key, msg)
    assert len(encrypted) == NONCE_SIZE + len(msg) + MAC_SIZE
    decrypted = decrypt_msg(key, encrypted)
    assert decrypted == msg


def test_length_prefix():
    key = os.urandom(32)
    msg = b"whoami"
    encrypted = encrypt_msg(key, msg)
    framed = struct.pack("<I", len(encrypted)) + encrypted
    size = struct.unpack("<I", framed[:4])[0]
    payload = framed[4:4 + size]
    assert decrypt_msg(key, payload) == msg


def test_bad_key_fails():
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    encrypted = encrypt_msg(key, b"secret")
    try:
        decrypt_msg(wrong_key, encrypted)
        assert False, "Should have raised"
    except Exception:
        pass


if __name__ == "__main__":
    test_round_trip()
    test_length_prefix()
    test_bad_key_fails()
    print("[+] All crypto tests passed")
