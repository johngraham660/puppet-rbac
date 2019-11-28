#! python3

import os
import sys
import requests
import json

#modules = ("requests", "json")
#
#for module in modules:
#  try:
#    import module
#  except ImportError as e:
#    print "import Error: %s" % e

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

username, password = open('credentials.txt').read().strip().split(',')
lifetime = "1y"
cert_file = 'ca.pem'
pemaster = 'master.example.com'

def __get_pemaster_cacert():

    cacert_url = 'https://master.example.com:8140/puppet-ca/v1/certificate/ca'
    cert_file = 'ca.pem'

    s = requests.Session()
    r = s.get(cacert_url, verify=False)

    f = open(cert_file, "w")
    f.write(r.content)

    return True

def __create_token(username, password, lifetime):
    '''
    Generates an authentication token

    Parameters:
    username  (str): The user account that should be used to authenticate with the puupet server
    password  (str): The password that authenticates the username provided.
    lifetimne (str): lifetime determines how long the authentication token is valid for

    Returns:
    str: Returns the authentication token string
    '''

    # ============================================
    # Ensure username, password params are strings
    # ============================================
    assert isinstance(username, str)
    assert isinstance(password, str)
    assert isinstance(lifetime, str)
   
    # ============================================================
    # Setup the values that wil be passed to the rbac-api endpoint
    # ============================================================
    token_url = 'https://master.example.com:4433/rbac-api/v1/auth/token'
    params = {"certfile": cert_file}
    data = {"login": username, "password": password, "lifetime": lifetime}
    headers = {'content-type': 'application/json'}

    # ==================
    # Submit the request
    # ==================
    s = requests.Session()
    r = s.post(token_url, data=json.dumps(data), params=params, headers=headers, verify=False)
    token = r.json()

    # ================
    # Return the token
    # ================
    return token['token'] 


def __create_rbac_user(token):
    '''
    Create an RBAC user

    '''

    assert isinstance(token, str)


def __create_rbac_role(token):
    '''
    Create an RBAC role and setup permissions
    '''

    assert isinstance(token, unicode)


def __get_user_ids(token):
    '''
    Gets the id's of all users configured on the PE master

    Parameters:
    token (unicode):

    Returns:
    dict: Returns a dictionary containing the username:id key value pairs
    '''

    assert isinstance(token, unicode)

    api_endpoint = 'https://master.example.com:4433/rbac-api/v1/users'
    params = {"certfile": cert_file}
    headers = {'content-type': 'application/json', 'X-Authentication': token}
    
    # ==================
    # Submit the request
    # ==================
    s = requests.Session()
    r = s.get(api_endpoint, params=params, headers=headers, verify=False)
    users = r.json()

    # ====================================================
    # Create a new dict to keep the username to id mapping
    # ====================================================
    username_to_id = {}

    for dict in users:
        print "username: %s, id: %s" % (dict['login'], dict['id'])

	login = dict['login']
	id = dict['id']

	ername_to_idsername_to_id[login] = id

    print username_to_id

def __get_role_ids(token, role):
    pass


if __name__ == '__main__':

    # ==========================================================================
    # Get the Puppet master CA certificate as we will need this for all requests
    # ==========================================================================
    __get_pemaster_cacert()

    # =================================
    # Generate a token for this session
    # =================================
    token = __create_token(username, password, lifetime)
    # =====================
    # Create the RBAC roles
    # =====================
    # rbac_role_names = ("Splunk", \
    #                    "Tyk API Gateway", \
    #     	       "websphere_task_runner", \
    #     	       "MongoDB Initialization" \
    #     	      )

    # for role_name in rbac_role_names:
    #   __create_rbac_role(token, role_name)

    # =====================
    # Create the RBAC users
    # =====================
    # __create_rbac_user(token)

    __get_user_ids(token)


