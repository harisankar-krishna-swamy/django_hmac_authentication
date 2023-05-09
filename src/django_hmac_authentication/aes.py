from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from django_hmac_authentication.padding import pad, unpad

block_size = 128


def aes_crypt(msg: bytes, key: bytes, iv: bytes, encrypt: bool = True):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    if encrypt:
        encryptor = cipher.encryptor()
        return encryptor.update(pad(msg, block_size)) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        return unpad(decryptor.update(msg) + decryptor.finalize())
