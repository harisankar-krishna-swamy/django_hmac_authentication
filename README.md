# django_hmac_authentication
Django hmac authentication with shared secret

* Django model with HMAC shared encrypted secret
* Authentication class `HMACAuthentication` 
* Reject requests earlier than configured timeout
* Supports `HMAC-SHA512`, `HMAC-SHA384`, `HMAC-SHA256`
* HMAC secret can be created with management command or obtained with a configured url
* Supports Javascript and Python clients

# 1. Install
`pip install django_hmac_authentication`

# 2. Configuration

## 2.1 settings.py

* Add `MAX_HMACS_PER_USER`  
  Default: 10  
* Add `HMAC_AUTH_REQUEST_TIMEOUT` in seconds. Requests earlier than this are rejected
  Default: `5`
* Add `django_hmac_authentication` to installed apps along with `rest_framework`.
* Add hmac authentication class to `REST_FRAMEWORK` in `settings.py`. 

* Example
```python
MAX_HMACS_PER_USER = 10
HMAC_AUTH_REQUEST_TIMEOUT = 4

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
        'django_hmac_authentication.authentication.HMACAuthentication',
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

Steps:

1. request body (data) -> json string in utf-8 -> hash -> **base64 of body hash**
2. **utc 8601 string**
3. string to sign = **base64 of body hash** + ";" + **utc 8601 string**
4. signature = hash (string to sign) -> base64

* Hash function is one of supported methods in Authorization header
* UTC time now in ISO 8601 format. Example `2023-05-07T14:15:37.862560+00:00`

# 6. Authorization header
* method: One of `HMAC-SHA512`, `HMAC-SHA384`, `HMAC-SHA256`
* api_key: Key used to identify the hmac secret used to generate signature
* signature: base64 signature
* request_utc: time in ISO 8601 set in signed string

`Syntax`: METHOD api_key;signature;request_utc_8601

Example
```python
'HMAC-SHA512 aa733037-e4c0-4f75-a864-df6c1966481b;6k3XaUREI6dDw6thyQWASJjzjsx1M7GOZAglguv0OElpRue1+gb7CK2n3JpzJGz9VcREw2y3rIW5zoZYEUY+0w==;2023-05-07T14:15:37.862560+00:00'
```
# 7. License
Apache2 License

# 8. Github
https://github.com/harisankar-krishna-swamy/django_hmac_authentication

# 9. See also
https://www.okta.com/au/identity-101/hmac/

https://docs.python.org/3/library/hashlib.html

https://learn.microsoft.com/en-us/azure/communication-services/tutorials/hmac-header-tutorial?pivots=programming-language-python
