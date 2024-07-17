import logging
from superset.security import SupersetSecurityManager

# class CustomSsoSecurityManager(SupersetSecurityManager):

    # def oauth_user_info(self, provider, response=None):
    #     logging.debug("Oauth2 provider: {0}.".format(provider))
    #     if provider == 'keycloak':
    #         # As example, this line request a GET to base_url + '/' + userDetails with Bearer  Authentication,
    # # and expects that authorization server checks the token, and response with user details
    #         me = self.appbuilder.sm.oauth_remotes[provider].get('userDetails').data
    #         logging.debug("user_data: {0}".format(me))
    #         return { 'name' : me['name'], 'email' : me['email'], 'id' : me['user_name'], 'username' : me['user_name'], 'first_name':'', 'last_name':''}
    # ...

class CustomSsoSecurityManager(SupersetSecurityManager):

    def oauth_user_info(self, provider, response=None):
        logging.debug("CustomSsoSecurityManager : Oauth2 provider: {0}.".format(provider))
        logging.debug("CustomSsoSecurityManager : Oauth2 oauth_remotes provider: {0}.".format(self.appbuilder.sm.oauth_remotes[provider]))

        if provider == 'keycloak':
            # Get the user info using the access token
            res = self.appbuilder.sm.oauth_remotes[provider].get('http://localhost:8080/realms/cbm-willowmore-dev/protocol/openid-connect/userinfo')
            logging.info(f"CustomSsoSecurityManager : userinfo response:{res.status_code}")
            for attr, value in vars(res).items():
                logging.info(attr, '=>', value)

            if res.status_code != 200:
                logging.error('CustomSsoSecurityManager : Failed to obtain user info: %s', res._content)
                return

            #dict_str = res._content.decode("UTF-8")
            me = res.data

            logging.debug("CustomSsoSecurityManager: user_data: %s", me)
            # return {
            #     'username' : 'admin',
            #     'name' : 'admin',
            #     'email' : 'admin@superset.com',
            #     'first_name': 'Superset',
            #     'last_name': 'Admin',
            #     'is_active': True, 
            # }
            {
                'username' : me['preferred_username'],
                'name' : me['name'],
                'email' : me['email'],
                'first_name': me['given_name'],
                'last_name': me['family_name'],
                'roles': me['roles'],
                'is_active': True,
            }