#! python3

import os
import sys
import requests
import json
import argparse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

username, password = open('credentials.txt').read().strip().split(',')
lifetime = "1y"
cert_file = 'ca.pem'
pemaster = 'master.example.com'


def __get_pemaster_cacert(pemaster):

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
    username  (str):The account that should be used to authenticate with the API # noqa: E501
    password  (str):The password that authenticates the username provided.
    lifetimne (str):lifetime determines how long the authentication token is valid for

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
    r = s.post(token_url, data=json.dumps(data),
               params=params,
               headers=headers,
               verify=False)
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
    # TODO: Parse users config file


def __create_rbac_role(token):
    '''
    Create an RBAC role and setup permissions
    '''

    assert isinstance(token, unicode)
    # TODO: Parse roles config file


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
    username_to_id = {}

    # ==================
    # Submit the request
    # ==================
    s = requests.Session()
    r = s.get(api_endpoint, params=params, headers=headers, verify=False)
    users = r.json()

    for dict in users:
        print "%s : %s" % (dict['login'], dict['id'])

    login = dict['login']
    id = dict['id']
    username_to_id[login] = id

    return username_to_id


def __get_role_ids(token):
    """
    <Doc String here>
    """
    assert isinstance(token, unicode)

    api_endpoint = 'https://master.example.com:4433/rbac-api/v1/roles'
    params = {"certfile": cert_file}
    headers = {'content-type': 'application/json', 'X-Authentication': token}
    rolename_to_id = {}

    # ==================
    # Submit the request
    # ==================
    s = requests.Session()
    r = s.get(api_endpoint, params=params, headers=headers, verify=False)
    roles = r.json()

    for dict in roles:
        print "role name: %s, id: %s" % (dict['display_name'], dict['id'])

    display_name = dict['display_name']
    id = dict['id']
    rolename_to_id[display_name] = id

    return rolename_to_id


if __name__ == '__main__':

    # ======================================
    # Section block for parsing cmdline args
    # ======================================
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server",
                        help="The Puppet Enterprise server hosting the API"
                        action="store_true")
    args = parser.parse_args()

    # ===================================================================
    # Get the master CA certificate as we will need this for all requests
    # ===================================================================
    # TODO: This needs to be written to an appropriate directory
    __get_pemaster_cacert(pemaster)

    # =================================
    # Generate a token for this session
    # =================================
    token = __create_token(username, password, lifetime)

    # =====================
    # Create the RBAC roles
    # =====================

    # =====================
    # Create the RBAC users
    # =====================
    # TODO: Parse external file that defines valid users.

    user_ids = __get_user_ids(token)
    role_ids = __get_role_ids(token)
    role_ids = __get_role_ids(token)
    print role_ids
