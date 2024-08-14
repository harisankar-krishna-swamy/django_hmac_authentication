import json

from vevde_security_utils.crypt.signatures import hash_content

encoding = 'utf-8'


def compose_authorization_header(
    digest: str, api_key: str, signature: str, utc_8601: str
):
    """
    Put together Authorization header string

    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'
    @param api_key: User's api_key
    @param signature: base64 signature
    @param utc_8601: The utc 8601 string that was also signed

    @return: authorization header string
    """
    return f'{digest} {api_key};{signature};{utc_8601}'


def prepare_string_to_sign(data: dict, utc_8601: str, digest: str):
    """
    Prepare a string to sign from data and utc_8601.
    string to sign = hash( json(data) ) + ';' + utc_8601
    @param data: data dict
    @param utc_8601: utc 8601 string to use in signature. use utc now if not provided
    @param digest: HMAC method. One of 'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'

    @return: string to sign
    """
    body = (
        None if not data else json.dumps(data, separators=(',', ':')).encode(encoding)
    )
    body_hash = hash_content(digest, body)
    string_to_sign = f';{utc_8601}'

    if body_hash:
        string_to_sign = f'{body_hash}' + string_to_sign
    return string_to_sign
