
# from flask_appbuilder.security.manager import (
#     AUTH_OID,
#     AUTH_REMOTE_USER,
#     AUTH_DB,
#     AUTH_LDAP,
#     AUTH_OAUTH,
# )
# import sys
# sys.path.append('/home/zhenjianlee/projects/supersetdigiHUB')
# from custom_sso_security_manager import CustomSsoSecurityManager

# App Icon
APP_ICON = "/static/assets/images/CBM-Black.png"


# Superset specific config
ROW_LIMIT = 5000

# Flask App Builder configuration
# Your App secret key will be used for securely signing the session cookie
# and encrypting sensitive information on the database
# Make sure you are changing this key for your deployment with a strong key.
# Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.
# You MUST set this for production environments or the server will refuse
# to start and you will see an error in the logs accordingly.
SECRET_KEY = '123456789'

# The SQLAlchemy connection string to your database backend
# This connection defines the path to the database that stores your
# superset metadata (slices, connections, tables, dashboards, ...).
# Note that the connection information to connect to the datasources
# you want to explore are managed directly in the web UI
# The check_same_thread=false property ensures the sqlite client does not attempt
# to enforce single-threaded access, which may be problematic in some edge cases
# SQLALCHEMY_DATABASE_URI = 'sqlite:////home/zhenjianlee/projects/supersetdigiHUB/superset.db?check_same_thread=false'
SQLALCHEMY_DATABASE_URI ='mysql+mysqlconnector://zhenjianlee:zhenjianLEE24!@localhost:3306/supersetdigiHUB' 

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []
# A CSRF token that expires in 1 year
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

# Set this API key to enable Mapbox visualizations
MAPBOX_API_KEY = ''

# Load Balancer - In SQLITE DB -Fixes the 'Failed to Fetch' Error In Development https://stackoverflow.com/questions/66689709/superset-there-was-an-error-fetching-the-favorite-status-failed-to-fetch
#ENABLE_PROXY_FIX=True

#Auth Section
# CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

# AUTH_TYPE = AUTH_OAUTH

# OAUTH_PROVIDERS=[
#      {
#         'name': 'keycloak',
#         'icon': 'fa-key',
#         'token_key': 'eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkNmMxYmY0NC1hMTIzLTQ5NWEtYTQ4Yy1hNDNmZDMxN2MzYmMifQ.eyJleHAiOjAsImlhdCI6MTcyMTAyNzY2NSwianRpIjoiMTM2MGEyODctY2ZhMi00MjU3LWIyODEtMjcwY2NlOTc2MDk3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9jYm0td2lsbG93bW9yZS1kZXYiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL2NibS13aWxsb3dtb3JlLWRldiIsInR5cCI6IlJlZ2lzdHJhdGlvbkFjY2Vzc1Rva2VuIiwicmVnaXN0cmF0aW9uX2F1dGgiOiJhdXRoZW50aWNhdGVkIn0.UHs-q8mm0n1Lxldq4WU3uScnLUkX-s2u3SpLXr4op-HraM4hvpDl0hC8dEn-IHvLDWKW64rPf3z4nFaeebxeGg',  # Keycloak uses 'access_token' for the access token
#         'remote_app': {
#             'client_id': 'supersetdigiHUB',
#             'client_secret': 'ZuAkVOJU7mg4Gc6OOda47TW4zUEbz9Mv',
#             'client_kwargs': {
#                 'scope': 'openid profile email',
#             },
#             'server_metadata_url': 'http://localhost:8080/realms/cbm-willowmore-dev/.well-known/openid-configuration',
#             'api_base_url': 'http://localhost:8080/realms/cbm-willowmore-dev/protocol/',
#         },
#     }
    
# ]

# Will allow user self registration, allowing to create Flask users from Authorized User
#AUTH_USER_REGISTRATION = True

# The default user self registration role
#AUTH_USER_REGISTRATION_ROLE = "Public"