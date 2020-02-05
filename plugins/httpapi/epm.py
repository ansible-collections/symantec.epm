# (c) 2019 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Security Automation Team
httpapi: epm
short_description: HttpApi Plugin for Symantec Endpoint Protection Manager (EPM)
description:
  - This HttpApi plugin provides methods to connect to Symantec Endpoint
    Protection over a HTTP(S)-based api.
version_added: "2.9"
"""

import json

from ansible.module_utils.basic import to_text, to_bytes
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.errors import AnsibleConnectionFailure, AnsibleAuthenticationFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError

BASE_HEADERS = {"Content-Type": "application/json"}


class HttpApi(HttpApiBase):
    def send_request(self, request_method, url, params=None, data=None, headers=None):
        headers = headers if headers else BASE_HEADERS

        if params:
            params_with_val = {}
            for param in params:
                if params[param] is not None:
                    params_with_val[param] = params[param]
            url = "{0}?{1}".format(url, urlencode(params_with_val))

        try:
            self._display_request(request_method)
            response, response_data = self.connection.send(
                url, data, method=request_method, headers=headers
            )
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def login(self, username, password):
        login_path = "/sepm/api/v1/identity/authenticate"
        data = {"username": username, "password": password}

        response, response_data = self.send_request(
            "POST", login_path, data=to_bytes(json.dumps(data))
        )

        try:
            self.connection._auth = {
                "Authorization": "Bearer {0}".format(response_data["token"])
            }
        except KeyError:
            raise AnsibleAuthenticationFailure(message="Failed to acquire login token.")

    def _display_request(self, request_method):
        self.connection.queue_message(
            "vvvv", "Web Services: %s %s" % (request_method, self.connection._url)
        )

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError("Invalid JSON response: %s" % response_text)

    def update_auth(self, response, response_text):
        token = response.info().get("token")
        # Set the 'Authorization' header
        if token:
            return {"Authorization": "Bearer {0}".format(token)}

        return None

    def logout(self):
        if self.connection._auth is not None:
            self.send_request("POST", "/sepm/api/v1/identity/logout",
                              data=to_bytes(json.dumps(self.connection._auth)))

            # Clean up tokens
            self.connection._auth = None
