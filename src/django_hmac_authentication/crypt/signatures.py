import base64
import hashlib
import hmac

encoding = 'utf-8'

digests_map = {
    'HMAC-SHA512': hashlib.sha512,
    'HMAC-SHA384': hashlib.sha384,
    'HMAC-SHA256': hashlib.sha256,
}


def hash_content(digest: str, content: bytes):
    """
    Compute hash on content using function specified by digest

    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'
    @param content: bytes to hash

    @return: base64 of hash
    """
    if not content:
        return None

    if digest not in digests_map.keys():
        raise ValueError(f'Unsupported HMAC function {digest}')

    func = digests_map[digest]
    hasher = func()
    hasher.update(content)
    hashed_bytes = hasher.digest()
    base64_encoded_bytes = base64.b64encode(hashed_bytes)
    content_hash = base64_encoded_bytes.decode(encoding)
    return content_hash


def sign_string(string_to_sign: str, secret: bytes, digest):
    """
    Sign a string with hmac secret using digest's hash function

    @param string_to_sign: string to sign
    @param secret: shared secret key to sign with
    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'

    @return: base64 string of signature
    """
    if digest not in digests_map.keys():
        raise ValueError(f'Unsupported HMAC function {digest}')
    encoded_string_to_sign = string_to_sign.encode(encoding)
    hashed_bytes = hmac.digest(
        secret, encoded_string_to_sign, digest=digests_map[digest]
    )
    encoded_signature = base64.b64encode(hashed_bytes)
    signature = encoded_signature.decode(encoding)
    return signature
