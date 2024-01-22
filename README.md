# django_hmac_authentication
Django hmac authentication with multiple encrypted hmac secrets per user

> :rocket: :rocket: Built on Debian, KDE and CI/CD on GitLab :penguin: :penguin: :rocket: :rocket: 
# Features
| #  | Feature                         | Description       |
| -- | ------------------------------- | ----------------- |
| 1  | Multiple hmac secrets per user  | Each secret is protected with a separate key |
| 2  | Django Model and Authentication | Django `ApiHMACKey` and Authentication classes `HMACAuthentication` for Django Rest Framework | 
| 3  | Obtain credentials              | Django management command or a configured url to get credentials |
| 4  | Reject stale requests           | Reject requests earlier than configured timeout and also with future timestamps |
| 5  | Supported HMAC hash functions   | `HMAC-SHA512`, `HMAC-SHA384`, `HMAC-SHA256` |
| 6  | Clients                         | Javascript and Python clients for programmatic access. See `example_django_project` and `Postman` collections |
| 7  | Auto-Revoke                     | Optional configuration to auto revoke keys after N failed attempts to authenticate |
| 8  | Auto-Expire                     | Optional `HMAC_EXPIRES_IN` configuration. If set HMAC keys will expire after interval |
| 9  | Performance (Caching)           | * Option to speedup using a cache in Django's `CACHES` settings.  <br/>* A `lru_cache` is enabled locally to save compute time to decode hmac key |
| 10 | Kill switch                     | An out-of-band capability to reject requests |
| 11 | Throttling                      | Throttling requests on hmac key used |
| 12 | Supported encryption ciphers    | `AES-256`, `CAMELLIA-256` to encrypt user's hmac secrets |
### What's new 
Camellia 256 cipher is used along with aes. Package now picks one of AES-256 or Camellia-256 to
secure users' HMAC secrets at runtime. Encryption now has two algorithms instead of just one. 
Client side changes not required. To use new feature just update package and run migrations. 

# 1. Install
`pip install django_hmac_authentication`

# 2. Configuration

## 2.1 settings.py 
See example configurations below.

#### 1. In Django `INSTALLED_APPS` 
Add `django_hmac_authentication` to INSTALLED_APPS
#### 2. In `REST_FRAMEWORK` 
Add HMAC authentication class to REST_FRAMEWORK settings dict.
#### 3. Package specific settings in `HMAC_AUTHENTICATION_SETTINGS` 

* `MAX_HMACS_PER_USER`  `Default: 10`. Maximum hmac secrets per user
* `HMAC_AUTH_REQUEST_TIMEOUT` Requests earlier than this are rejected. Default: `5` in seconds 
* Optional settings
  * `HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD`Max attempts to authenticate after which key is auto-revoked 
  * `HMAC_EXPIRES_IN` HMAC keys will auto-expire after this period in hours, minutes or seconds.  Example`'1h'`, `'5m'`, `'3600s'` 
  * `HMAC_CACHE_ALIAS` Alias of a cache backend in Django's `CACHES` settings. When set, the cache specified by the 
     alias is used to cache hmac keys. Example: `hmac_cache`. Default: None (i.e caching disabled) 
  * `HMAC_KILL_SWITCH` If set, enables checking cache to force-reject requests for certain keys. `HMAC_CACHE_ALIAS` must be set. 
     > Note: The hmac keys in this package can be disabled and enabled using the admin interface. 
     This switch helps when that option is not feasible and out of band intervention is needed. 
     See `example_django_project/scripts/out_of_band_hmac_kill_switch.py` for a sample program that demonstrates switching keys on/off. Depending on cache backend used and CACHES configuration in settings.py, the cache key needs 
     to be formatted. 
     [See Django cache key formatting based on configuration](https://github.com/django/django/blob/64cea1e48f285ea2162c669208d95188b32bbc82/django/core/cache/backends/base.py#L32) 
  * `Throttling` Add throttling class in `REST_FRAMEWORK` > `DEFAULT_THROTTLE_CLASSES` as  
    `django_hmac_authentication.throttling.HMACApiKeyRateThrottle`. Throttling uses cache and `HMAC_CACHE_ALIAS` must be set. By default all hmac keys are created with rate `200/min`. Rate can be changed on admin interface.  

#### Example
```python
HMAC_AUTHENTICATION_SETTINGS = {
    'MAX_HMACS_PER_USER':10,
    'HMAC_AUTH_REQUEST_TIMEOUT': 4,
    # Optional configurations
    'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD': 10,
    'HMAC_EXPIRES_IN': '5m',
    # This cache alias must be defined in Django's CACHES. 
    # See https://docs.djangoproject.com/en/4.2/ref/settings/#caches
    'HMAC_CACHE_ALIAS': 'hmac_cache',
    'HMAC_KILL_SWITCH': True
}

INSTALLED_APPS = [
    ...,
    'rest_framework',
    'django_hmac_authentication',
    ...
]

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        # Add authentication class
        'django_hmac_authentication.authentication.HMACAuthentication',
    ],
    # Throttling
    'DEFAULT_THROTTLE_CLASSES': [
        'django_hmac_authentication.throttling.HMACApiKeyRateThrottle'
    ],
}
```

## 2.2 urls.py
Add url to obtain HMAC key and secret 
```python
...
from django_hmac_authentication.views import CreateApiHMACKey

urlpatterns = [
    ...,
    # django_hmac_authentication
    path('obtain-hmac-api-key/', 
         CreateApiHMACKey.as_view(), 
         name='api_hmac_key'),
    ...
]
```
## 2.3 Run migrations 

```python
python manage.py migrate django_hmac_authentication
```
# 3. Usage

## 3.1 Obtain HMAC key and secret 

### 3.1.1 Using management command
Use management command to create a HMAC API key with secret for a user
```python
python manage.py create_hmac_for_user bob
{"api_key": "f4c3801c-a277-4fcb-92bb-44cb814026f6", "api_secret": "vEOQRdvaK4jyeLKGNP9oqpYTUvt/GZWbGG6iNmnDh8c=", "message": "These credentials will be lost forever if not stored now"}
```

### 3.1.2 Using curl
```python
# Use the url from configuration
curl -X POST -H "Content-Type: application/json" -d '{"username":"bob", "password":"bobspassword"}' http://127.0.0.1:8000/obtain-hmac-api-key/ 
{"api_key":"7ebc25d7-d237-4f90-b4ad-98f0c228fc1e","api_secret":"EDQppq0B3rIxvaA7PyPUHPF6kiXTnnbvnMiZDzYFSRA=","message":"These credentials will be lost forever if not stored now"}
```

# 4. Sign requests client-side

## 4.1 Javascript client
See `example_django_project/javascript_topman_collection` folder

A postman collection with environment is provided which can be imported to Postman.
A prerequest script for generating the signature is provided (same as included in postman collection).

## 4.2 Python client
See `example_django_project/example_python_client.py`

# 5. Signature

# 5.1 How is it calculated

Signature is calculated on hash( request body json ) + utc 8601

```text
request data
    │
    ▼
  json
    │
    ▼
  hash  +   ;  +  utc 8601
 ────────────┬─────────────
             │
             ▼
         signature
```

* Hash function is one of supported methods in Authorization header
* UTC time now in ISO 8601 format. Example `2023-05-07T14:15:37.862560+00:00`

# 6. Authorization header

`Syntax`: `METHOD` `api_key;signature;request_utc_8601`

* method: One of `HMAC-SHA512`, `HMAC-SHA384`, `HMAC-SHA256`
* api_key: Key used to identify the hmac secret used to generate signature
* signature: base64 signature
* request_utc: time in ISO 8601 set in signed string

Example
```python
'HMAC-SHA512 aa733037-e4c0-4f75-a864-df6c1966481b;6k3XaUREI6dDw6thyQWASJjzjsx1M7GOZAglguv0OElpRue1+gb7CK2n3JpzJGz9VcREw2y3rIW5zoZYEUY+0w==;2023-05-07T14:15:37.862560+00:00'
```
# 7. Protecting user's hmac secret
```text
Django settings.SECRET_KEY                 salt per user
           │                               │   │
           │                               │   │
           └───────────►   pbkdf2_hmac  ◄──┘   │
                                │              │
                                │              │
                                ▼              │
                              256 bit key      │
                                │              │
                                │              │
                                ▼              │
   encrypt user secret  ◄───── aes/camellia    │
                                ▲              │
                                │              │
                               iv ◄────────────┘
```
# 8. License
Apache2 License

# 9. Github
https://github.com/harisankar-krishna-swamy/django_hmac_authentication

# 10. See also
https://www.okta.com/au/identity-101/hmac/

https://docs.python.org/3/library/hashlib.html

https://learn.microsoft.com/en-us/azure/communication-services/tutorials/hmac-header-tutorial?pivots=programming-language-python
