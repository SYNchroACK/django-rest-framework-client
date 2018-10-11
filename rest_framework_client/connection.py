"""
This API client generically supports Django Rest Framework based APIs

It is based on https://github.com/samgiles/slumber, but customized for
Django Rest Frameworks, and the use of TokenAuthentication.

Usage:
    # Assuming
    # v1_api_router.register(r'some_model', SomeModelViewSet)
    options = {
       'DOMAIN': 'http://127.0.0.1:8000',
       'API_PREFIX': 'api/v1',
       'TOKEN_TYPE': 'jwt',
       'TOKEN_FORMAT': 'JWT {token}',
       'LOGIN': 'auth/api-jwt-auth/',
       'LOGOUT': 'auth/logout/',
    }

    api = RestApi(options)
    api.login(email='user1@test.com', password='user1')
    obj_list = api.some_model.get()
    logger.debug('Found {0} groups'.format(obj_list['count']))
    obj_one = api.some_model(1).get()
    api.logout()
"""

from urllib.parse import urljoin

import requests
import json
import os

from .exceptions import *


DEFAULT_OPTIONS = {
    'DOMAIN': 'http://127.0.0.1',
    'PREFIX_PATH': '/',
    'LOGIN_PATH': '/auth/token/login/',
    'LOGOUT_PATH': '/auth/token/logout/',
    'TOKEN_KEY': 'auth_token',
    'TOKEN_FORMAT': 'Token {token}',
    'HEADERS': {
        'Content-Type': 'application/json'
    }
}


def join_url(paths):
    url = ""
    for path in paths:
        url = urljoin(url, path)
    return url


class RESTResource(object):
    """
    Resource provides the main functionality behind a Django Rest Framework based API. It handles the
    attribute -> url, kwarg -> query param, and other related behind the scenes
    python to HTTP transformations. It's goal is to represent a single resource
    which may or may not have children.
    """
    _store = {}

    def __init__(self, *args, **kwargs):
        self._store = kwargs

    def __call__(self, id=None):
        """
        Returns a new instance of self modified by one or more of the available
        parameters. These allows us to do things like override format for a
        specific request, and enables the api.resource(ID).get() syntax to get
        a specific resource by it's ID.
        """

        url = join_url([self._store['base_url'], str(id)+"/"])

        kwargs = self._copy_kwargs(self._store)
        kwargs.update({'base_url': url})

        return self._get_resource(**kwargs)

    def __getattr__(self, item):

        # Don't allow access to 'private' by convention attributes.

        if item.startswith("_"):
            raise AttributeError(item)

        url = join_url([self._store['base_url'], item+"/"])

        kwargs = self._copy_kwargs(self._store)
        kwargs.update({'base_url': url})

        return self._get_resource(**kwargs)

    def _copy_kwargs(self, dictionary):
        kwargs = {}
        for key, value in self._iterator(dictionary):
            kwargs[key] = value

        return kwargs

    def _iterator(self, d):
        """
        Helper to get and a proper dict iterator with Py2k and Py3k
        """
        try:
            return d.iteritems()
        except AttributeError:
            return d.items()

    def _check_for_errors(self, resp, url):

        if 400 <= resp.status_code <= 499:
            exception_class = HttpNotFoundError if resp.status_code == 404 else HttpClientError
            raise exception_class("Client Error %s: %s" % (resp.status_code, url), response=resp, content=resp.content)
        elif 500 <= resp.status_code <= 599:
            raise HttpServerError("Server Error %s: %s" % (resp.status_code, url), response=resp, content=resp.content)

    def _handle_redirect(self, resp, **kwargs):
        # @@@ Hacky, see description in __call__
        resource_obj = self(url_override=resp.headers["location"])
        return resource_obj.get(**kwargs)

    def _try_to_serialize_response(self, resp):
        if resp.status_code in [204, 205]:
            return

        if resp.content:
            if type(resp.content) == bytes:
                try:
                    encoding = requests.utils.guess_json_utf(resp.content)
                    return json.loads(resp.content.decode(encoding))
                except Exception:
                    return resp.content
            return json.loads(resp.content)
        else:
            return resp.content

    def _process_response(self, resp):

        self._check_for_errors(resp, self.url())

        if 200 <= resp.status_code <= 299:
            return self._try_to_serialize_response(resp)
        else:
            return  # @@@ We should probably do some sort of error here? (Is this even possible?)

    def url(self, args=None):
        url = self._store["base_url"]

        if args:
            url += '?{0}'.format(args)
        return url

    def _get_header(self):
        headers = DEFAULT_OPTIONS['HEADERS']
        if self._store['token']:
            headers['Authorization'] = self._store['token_format'].format(token=self._store["token"])

        return headers

    def get(self, **kwargs):
        args = None
        if 'extra' in kwargs:
            args = kwargs['extra']
        resp = requests.get(self.url(args), headers=self._get_header())
        return self._process_response(resp)

    def post(self, data=None, **kwargs):
        if data:
            payload = json.dumps(data)
        else:
            payload = None

        resp = requests.post(self.url(), data=payload, headers=self._get_header())
        return self._process_response(resp)

    def patch(self, data=None, **kwargs):
        if data:
            payload = json.dumps(data)
        else:
            payload = None

        resp = requests.patch(self.url(), data=payload, headers=self._get_header())
        return self._process_response(resp)

    def put(self, data=None, **kwargs):
        if data:
            payload = json.dumps(data)
        else:
            payload = None

        resp = requests.put(self.url(), data=payload, headers=self._get_header())
        return self._process_response(resp)

    def delete(self, **kwargs):

        resp = requests.delete(self.url(), headers=self._get_header())

        if 200 <= resp.status_code <= 299:
            if resp.status_code == 204:
                return True
            else:
                return True  # @@@ Should this really be True?
        else:
            return False

    def _get_resource(self, **kwargs):
        x = self.__class__(**kwargs)
        return self.__class__(**kwargs)

class RESTAPI(object):

    resource_class = RESTResource
    options = None
    token = None
    base_url = None

    def __init__(self, options={}):
        
        for option in DEFAULT_OPTIONS.keys():
            if option not in options:
                options[option] = DEFAULT_OPTIONS[option]

        self.options = options

        if self.options['PREFIX_PATH'] == DEFAULT_OPTIONS['PREFIX_PATH']:
            self.base_url = self.options['DOMAIN']
        else:
            self.base_url = join_url([self.options['DOMAIN'], self.options['PREFIX_PATH']])

    def set_token(self, token: str):
        self.token = token

    def login(self, credentials: dict):

        if credentials is None:
            raise RestBaseException("Credentials not provided")

        url = join_url([self.base_url, self.options['LOGIN_PATH']])
              
        data = json.dumps(credentials)

        response = requests.post(url, data=data, headers=self.options['HEADERS'])

        if response.status_code != 200:
            return False
            
        content = json.loads(response.content.decode())

        if self.options['TOKEN_KEY'] in content:
            self.token = content[self.options['TOKEN_KEY']]
        else:
            raise RestBaseException("Token not found on response")

        return True

    def logout(self):

        url = join_url([self.base_url, self.options['LOGOUT_PATH']])
              

        headers = self.options['HEADERS']
        headers['Authorization'] = self.options['TOKEN_FORMAT'].format(token=self.token)

        response = requests.post(url, headers=headers)
        
        if response.status_code != 204:
            return False

        self.token = None
        return True

    def __getattr__(self, item):
        """
        Instead of raising an attribute error, the undefined attribute will
        return a Resource Instance which can be used to make calls to the
        resource identified by the attribute.
        """

        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        kwargs = {
            'token': self.token,
            'token_format': self.options['TOKEN_FORMAT'],
            'base_url': join_url([self.base_url, item+"/" ]),
        }
        return self._get_resource(**kwargs)

    def _get_resource(self, **kwargs):
        return self.resource_class(**kwargs)