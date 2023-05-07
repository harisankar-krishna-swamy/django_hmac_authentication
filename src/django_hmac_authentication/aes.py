from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pad(msg: bytes, block_size):
    pad_len = block_size - len(msg) % block_size
    return msg + (bytes([pad_len]) * pad_len)


def unpad(msg: bytes):
    return msg[: -ord(msg[-1:])]


def aes_crypt(msg: bytes, key: bytes, iv: bytes, encrypt: bool = True):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    if encrypt:
        encryptor = cipher.encryptor()
        return encryptor.update(pad(msg, 128)) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        return unpad(decryptor.update(msg) + decryptor.finalize())
