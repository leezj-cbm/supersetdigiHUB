from flask_appbuilder.security.manager import (
    AUTH_DB,
    AUTH_LDAP,
    AUTH_OAUTH,
    AUTH_OID,
    AUTH_REMOTE_USER
)

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
ENABLE_PROXY_FIX=True

# Keycloak OAUTH
from custom_sso_security_manager import CustomSsoSecurityManager
CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

AUTH_TYPE = AUTH_DB
AUTH_ROLE_ADMIN = 'My Admin Role Name'
AUTH_ROLE_PUBLIC = 'My Public Role Name'

AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "My Public Role Name"

# registration configs
AUTH_USER_REGISTRATION = True  # allow users who are not already in the FAB DB
AUTH_USER_REGISTRATION_ROLE = "Public"  # this role will be given in addition to any AUTH_ROLES_MAPPING

OAUTH_PROVIDERS=[
     {
        "name": "keycloak",
        "icon": "fa-key",
        "token_key": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkNmMxYmY0NC1hMTIzLTQ5NWEtYTQ4Yy1hNDNmZDMxN2MzYmMifQ.eyJleHAiOjAsImlhdCI6MTcyMTA5NDg1MywianRpIjoiNGFlN2Y3N2ItOTcxZC00MmVkLWI2N2MtMmM0OGNjNzM4YTgyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9jYm0td2lsbG93bW9yZS1kZXYiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL2NibS13aWxsb3dtb3JlLWRldiIsInR5cCI6IlJlZ2lzdHJhdGlvbkFjY2Vzc1Rva2VuIiwicmVnaXN0cmF0aW9uX2F1dGgiOiJhdXRoZW50aWNhdGVkIn0.gkYsNZIq4RWlWCRtmqg2ftvg4StwuqRq313GaQhj3RU9-YNpRZOBBfYbSD8qHTUQPnSLpepVqEZiZje9pTf1fQ",
        "remote_app": {
            "client_id": "supersetdigiHUB",
            "client_secret": "ZuAkVOJU7mg4Gc6OOda47TW4zUEbz9Mv",
            "api_base_url": "https://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect",
            "client_kwargs": {
                "scope": "email profile"
            },
            "access_token_url": "http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/token",
            "authorize_url": "http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/auth",
            "request_token_url": None,
        },
    },
]
# a mapping from the values of `userinfo["role_keys"]` to a list of FAB roles
AUTH_ROLES_MAPPING = {
    "FAB_USERS": ["User"],
    "FAB_ADMINS": ["Admin"],
}

# if we should replace ALL the user's roles each login, or only on registration
AUTH_ROLES_SYNC_AT_LOGIN = True

# force users to re-auth after 30min of inactivity (to keep roles in sync)
PERMANENT_SESSION_LIFETIME = 1800
