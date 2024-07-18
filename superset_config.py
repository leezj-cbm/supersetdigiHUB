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
#------------------------
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

# Load Balancer
ENABLE_PROXY_FIX=True

# Proxy Fix Configuration
PROXY_FIX_CONFIG = {
    "x_for": 1,
    "x_proto": 1,
    "x_host": 1,
    "x_port": 1,
    "x_prefix": 1,
}

# Logging
DEBUG = True

# Security Configuration
#-----------------------

SESSION_COOKIE_HTTPONLY = True  # Prevent cookie from being read by frontend JS?
SESSION_COOKIE_SECURE = True  # Prevent cookie from being transmitted over non-tls?
SESSION_COOKIE_SAMESITE: None

AUTH_RATE_LIMITED= True
RATELIMIT_ENABLED =True


# Keycloak OAUTH
#----------------
import sys
sys.path.append("/home/zhenjianlee/projects/supersetdigiHUB")

#AUTH_TYPE = AUTH_DB
AUTH_TYPE = AUTH_OID
SECRET_KEY: 'QjKTzMT8yvMDOH8EqKpuHJSGp0tfBEX3'
OIDC_CLIENT_SECRETS =  '/home/zhenjianlee/projects/supersetdigiHUB/client_secret.json'
OIDC_ID_TOKEN_COOKIE_SECURE = True
OIDC_OPENID_REALM: "cbm-willowmore-dev"
OIDC_INTROSPECTION_AUTH_METHOD: 'client_secret_post'

from keycloak_security_manager import OIDCSecurityManager
CUSTOM_SECURITY_MANAGER = OIDCSecurityManager
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Gamma"
AUTH_ROLES_SYNC_AT_LOGIN = True  # Sync roles at login
AUTH_USER_REGISTRATION_ROLE_JMESPATH = "roles[*].name"

OAUTH_PROVIDERS=[
     {
        "name": "keycloak",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "supersetdigiHUB",
            "client_secret": "QjKTzMT8yvMDOH8EqKpuHJSGp0tfBEX3",
            "api_base_url": "http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/",
            "client_kwargs": {
                "scope": "email profile"
            },
            "access_token_url": "http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/token",
            "authorize_url": "http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/auth",
            "request_token_url": None,
            "base_url": "https://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect",
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
