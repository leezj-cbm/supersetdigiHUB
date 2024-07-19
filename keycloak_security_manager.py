from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user,logout_user,current_user,fresh_login_required
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request,
    make_response,
)
import logging
import requests

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
        logging.debug("🔵 KeyCloak_Security_Manager: Login ")
        
        @self.appbuilder.sm.oid.require_login 
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            userInfo =oidc.user_getinfo('cookie_id_token')
            logging.debug(f"🔵 KeyCloak_Security_Manager: userInfo:{str(userInfo)}")
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
        logging.debug(f"🔵 KeyCloak_Security_Manager: Logout")
        oidc = self.appbuilder.sm.oid   
        redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login   
        oidc.logout()
        super(AuthOIDCView, self).logout()
        logout_user() #flask-login library
        client_id = oidc.client_secrets.get('client_id')
        id_token = self.get_id_token()
        cookieInitial = request.cookies.get('session')
        # log out redirect
        # response = make_response(redirect(oidc.client_secrets.get('issuer') + 
        #                                   '/protocol/openid-connect/logout?post_logout_redirect_uri='+
        #                                   quote(redirect_url)+f"&client_id={client_id}&id_token_hint={id_token}"))
        response = make_response(redirect(oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout'))
        self.modify_or_delete_cookie(response,cookieInitial)
        return response
    
    def modify_or_delete_cookie(self,response,cookieInitial):
        logging.debug(f"🔵 KeyCloak_Security_Manager: Attempting to delete / modify cookie ")
        response.set_cookie('oidc_id_token',value='',max_age=0,expires=0, path='/',domain=request.host,secure=False, httponly=False, samesite=None)
        response.delete_cookie('oidc_id_token',path='/',domain=request.host)
        cookieAfter = request.cookies.get('session')
        if cookieAfter == None :
            logging.debug(f"🟢 KeyCloak_Security_Manager: Succesful cookie deletion")
        elif cookieInitial != cookieAfter:
            logging.debug(f"🟢 KeyCloak_Security_Manager: Succesful cookie modification")
        else:
            if cookieAfter == cookieInitial:
                logging.debug(f"🔴 KeyCloak_Security_Manager: Unsuccesful cookie modification ")
            else:
                logging.debug(f"🔴 KeyCloak_Security_Manager: Unsuccesful cookie deletion ")    
        
    def get_id_token(self):
        sm=self.appbuilder.sm
        oidc=sm.oid
        token_uri = oidc.client_secrets.get('token_uri')
        client_id = oidc.client_secrets.get('client_id')
        client_secret = oidc.client_secrets.get('client_secret')
        refresh_token=oidc.get_refresh_token()
        
        data={
            'grant_type':'refresh_token',
            'client_id':client_id,
            'client_secret': client_secret,
            'refresh_token' :refresh_token,
        }
        logging.debug(f"🔵 KeyCloak_Security_Manager: Requesting for refresh token") 
        response= requests.post(token_uri,data=data,verify=False,)
        
        if response.status_code == 200:
            tokens=response.json()
            id_token= tokens.get('id_token')
            logging.debug(f"🟢 KeyCloak_Security_Manager: Succesfully obtained id_token") 
            return id_token
        else:
            logging.debug(f"🟡 KeyCloak_Security_Manager: Could not obtain id_token , code :{response.status_code} message:{response.text} ") 
        return None
            
        
        
    
    
