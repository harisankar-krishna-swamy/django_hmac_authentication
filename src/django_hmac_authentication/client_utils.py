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
