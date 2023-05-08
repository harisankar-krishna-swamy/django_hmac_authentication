# django_hmac_authentication
Django hmac authentication with shared secret

* Django model with api key and hmac secret
* HMAC shared secret for user is protected with AES 
* AES key and iv derived from Django `SECRET_KEY` and random salt per user
* Authentication class `HMACAuthentication` 
* Reject requests earlier than configured timeout
* Supports `HMAC-SHA512`, `HMAC-384`, `HMAC-256`

# 1. Github
https://github.com/harisankar-krishna-swamy/django_hmac_authentication

# 2. Install
`pip install django_hmac_authentication`

# 3. Configuration
In `settings.py`

* Add `MAX_HMACS_PER_USER`  
  Default: 10  
* Add `HMAC_AUTH_REQUEST_TIMEOUT` in seconds. Requests earlier than this are rejected
  Default: `5`

Example
```python
MAX_HMACS_PER_USER = 10
HMAC_AUTH_REQUEST_TIMEOUT = 4
``` 

* Add `django_hmac_authentication` to installed apps along with `rest_framework`.  

Example  
```python
INSTALLED_APPS = [
    ...,
    'rest_framework',
    'django_hmac_authentication',
    ...
]
``` 
* Add hmac authentication class to `REST_FRAMEWORK` in `settings.py`.  

Example
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_hmac_authentication.authentication.HMACAuthentication',
    ],
}
```

Run migrations
```python
python manage.py migrate django_hmac_authentication
```
# 4. Usage

### 4.1 management command
Use management command to create a HMAC API key with secret
```python
python manage.py create_hmac_for_user bob
{"api_key": "f4c3801c-a277-4fcb-92bb-44cb814026f6", "api_secret": "vEOQRdvaK4jyeLKGNP9oqpYTUvt/GZWbGG6iNmnDh8c=", "message": "These credentials will be lost forever if not stored now"}
```

# 5. Signature fields

* Hash of request body. Hash function depends on one of the supported methods in Authorization header
* UTC time now in ISO 8601 format. Example `2023-05-07T14:15:37.862560+00:00`
*  

# 6. Authorization header
* method: One of `HMAC-SHA512`, `HMAC-SHA384`, `HMAC-SHA256`
* api_key: Key used to identify the hmac secret used to generate signature
* signature: base64 signature
* request_utc: time in ISO 8601 set in signed string

`Syntax`: method api_key;signature;request_utc

Example
```python
'HMAC-SHA512 aa733037-e4c0-4f75-a864-df6c1966481b;6k3XaUREI6dDw6thyQWASJjzjsx1M7GOZAglguv0OElpRue1+gb7CK2n3JpzJGz9VcREw2y3rIW5zoZYEUY+0w==;2023-05-07T14:15:37.862560+00:00'
```
# 7. License
Apache2 License

# 8. See also
https://www.okta.com/au/identity-101/hmac/

https://docs.python.org/3/library/hashlib.html

https://learn.microsoft.com/en-us/azure/communication-services/tutorials/hmac-header-tutorial?pivots=programming-language-python



