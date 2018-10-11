from rest_framework_client.connection import RESTAPI

import sys


options = {
    'DOMAIN': 'http://192.168.56.55',
    'PREFIX_PATH': '/',
    'LOGIN_PATH': '/auth/token/login/',
    'LOGOUT_PATH': '/auth/token/logout/',
    'TOKEN_TYPE': 'auth_token',
    'TOKEN_FORMAT': 'Token {token}',
}

credentials = {
    'email': 'example@example.com',
    'username': 'example',
    'password': 'password',
}

api = RESTAPI(options)

print("== User LOGIN")
if not api.login(credentials):
    print("Login failed ...")    
    sys.exit(-1)

print("== Systems GET")
systems = api.systems.get()

print(systems)

if systems:
    print("== Systems DELETE")
    print("Deleting: %s" % systems[0])
    res = api.systems(systems[0]['id']).delete()
    print(res)

system = {
    'hostname': 'test1',
    'ip': '8.8.8.8',
    'netmask': '255.255.255.0',
    'broadcast': '192.168.56.255',
    'interface': 'eth1'
}

print("== Systems POST")
print("Creating: %s" % system)
api.systems.post(system)

systems = api.systems.get()

system = {
    'hostname': 'test2',
    'ip': '8.8.3.2',
    'netmask': '255.255.255.0',
    'broadcast': '192.168.56.255',
    'interface': 'eth1'
}

print("Putting: %s" % system)
api.systems(systems[0]['id']).put(system)

system = {
    'broadcast': '192.168.56.252',
    'interface': 'eth4'
}

print("Patching: %s" % system)
api.systems(systems[0]['id']).patch(system)

if api.logout():
    print("Logout successfull")
else:
    print("Logout not successfull")
