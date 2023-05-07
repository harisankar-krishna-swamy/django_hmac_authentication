# django_hmac_authentication

Django hmac authentication with shared secret

* Django model with api key and hmac secret
* HMAC shared secret for user is protected with AES 
* AES key and iv derived from Django `SECRET_KEY` and random salt
* Authentication class `HMACAuthentication` 
* Reject requests earlier than configured timeout

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
# 4. License
Apache2 License

# 5. See also
https://www.okta.com/au/identity-101/hmac/

https://learn.microsoft.com/en-us/azure/communication-services/tutorials/hmac-header-tutorial?pivots=programming-language-python



