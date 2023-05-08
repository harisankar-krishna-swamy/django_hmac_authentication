import base64
import datetime
import hashlib
import hmac
import json

from rest_framework.exceptions import ValidationError

encoding = 'utf-8'


digests_map = {
    'HMAC-SHA512': hashlib.sha512,
    'HMAC-SHA384': hashlib.sha384,
    'HMAC-SHA256': hashlib.sha256,
}


def hash_content(digest: str, content: bytes):
    """
    Compute hash of content using hash function of digest

    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'
    @return: base64 of hash
    """
    if digest not in digests_map.keys():
        raise ValidationError(f'Unsupported HMAC function {digest}')

    func = digests_map[digest]
    hasher = func()
    hasher.update(content)
    hashed_bytes = hasher.digest()
    base64_encoded_bytes = base64.b64encode(hashed_bytes)
    content_hash = base64_encoded_bytes.decode('utf-8')
    return content_hash


def message_signature(message: str, secret: bytes, digest):
    """
    Sign message with hmac secret using digest hash function

    @param message: string to sign
    @param secret: Shared hmac secret key to sign with
    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'
    @return: base64 string of signature
    """
    if digest not in digests_map.keys():
        raise ValidationError(f'Unsupported HMAC function {digest}')
    encoded_string_to_sign = message.encode(encoding)
    hashed_bytes = hmac.digest(
        secret, encoded_string_to_sign, digest=digests_map[digest]
    )
    encoded_signature = base64.b64encode(hashed_bytes)
    signature = encoded_signature.decode(encoding)
    return signature


def compose_authorization_header(digest, api_key, signature, utc_8601):
    """
    Put together Authorization header string

    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'
    @param api_key: User's api_key
    @param signature: base64 signature for request
    @param utc_8601: The utc 8601 string that was also signed

    @return: authorization header string
    """
    return f'{digest} {api_key};{signature};{utc_8601}'


def hmac_sign(req_data: dict, api_secret: bytes, digest: str):
    """
    Builds a signature from request data (json) and utc time in ISO8601 format string

    @param req_data: data dict that goes into request body as json
    @param api_secret: api_secret for user
    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'

    @return: signature string and ISO8601 time string for authorization header
    """
    body = '' if not req_data else json.dumps(req_data)
    hash_body = hash_content(digest, body.encode('utf-8'))
    utc_8601 = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    signature = message_signature(f'{hash_body};{utc_8601}', api_secret, digest)
    return signature, utc_8601
