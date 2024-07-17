from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request
)
import logging

class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid
        logging.debug("🟡 KeyCloak_Security_Manager: Login ")
        @self.appbuilder.sm.oid.require_login #route to keycloak using security manager and oid library
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            logging.debug(f"🟡 KeyCloak_Security_Manager: User:{user}")
            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
                user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
                                   info.get('email'), sm.find_role('Gamma'))
                logging.debug(f"🟡 KeyCloak_Security_Manager: User is None :{user}")
            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        logging.debug("🟡 KeyCloak_Security_Manager: Logout ")
        oidc = self.appbuilder.sm.oid
        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
        # return redirect(
        #     oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + quote(redirect_url))
        return redirect(
            oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout')


# class OIDCSecurityManager(SupersetSecurityManager):
#     def __init__(self, appbuilder):
#         super(OIDCSecurityManager, self).__init__(appbuilder)
#         if self.auth_type == AUTH_OID:
#             self.oid = OpenIDConnect(self.appbuilder.get_app)
#         self.authoidview = AuthOIDCView
# class AuthOIDCView(AuthOIDView):
#     @expose('/logout-session/', methods=['GET'])
#     def logoutSession(self):
#         logout_user()
#         session.clear()
#         return 'You have been logged out'
#     @expose('/login/', methods=['GET', 'POST'])
#     def login(self, flag=True):
#         sm = self.appbuilder.sm
#         oidc = sm.oid
#         superset_roles = ["Admin", "Alpha", "Gamma", "Public", "granter", "sql_lab"]
#         default_role = "Gamma"
#         @self.appbuilder.sm.oid.require_login
#         @self.appbuilder.sm.oid.accept_token()
#         def handle_login():
#             user = sm.auth_user_oid(oidc.user_getfield('email'))
#             info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email', 'superset_role'])
#             print(info)
#             if user is None:
#                 info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email', 'superset_role'])
#                 print(info)
#                 roles_str = info.get('superset_role', '')
#                 roles = [role.strip() for role in roles_str.split(',') if role.strip() in superset_roles]
#                 roles += [default_role, ] if not roles else []
#                 roles_objects = [sm.find_role(role) for role in roles if sm.find_role(role)]
#                 if not roles_objects:
#                     # Handle the case when no valid roles are found
#                     print("No valid roles found for the user.")
#                     # Log an error or handle this case.
#                 user = sm.add_user(info.get('preferred_username'),
#                                 info.get('given_name', ''),
#                                 info.get('family_name', ''),
#                                 info.get('email'),
#                                 roles_objects)
#             login_user(user, remember=False)
#             return redirect(self.appbuilder.get_url_for_index)
#         return handle_login()
#     @expose('/logout/', methods=['GET', 'POST'])
#     def logout(self):
#         oidc = self.appbuilder.sm.oid
#         oidc.logout()
#         super(AuthOIDCView, self).logout()
#         redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
#         return redirect(
#             oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout')