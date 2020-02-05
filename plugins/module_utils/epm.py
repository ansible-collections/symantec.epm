#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.module_utils.urls import CertificateError
from ansible.module_utils.six.moves.urllib.parse import urlencode, quote_plus
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.connection import Connection
from ansible.module_utils._text import to_text

import json


def find_dict_in_list(some_list, key, value):
    text_type = False
    try:
        to_text(value)
        text_type = True
    except TypeError:
        pass
    for some_dict in some_list:
        if key in some_dict:
            if text_type:
                if to_text(some_dict[key]).strip() == to_text(value).strip():
                    return some_dict, some_list.index(some_dict)
            else:
                if some_dict[key] == value:
                    return some_dict, some_list.index(some_dict)
    return None


class EPMRequest(object):
    def __init__(self, module, headers=None, not_rest_data_keys=None):

        self.module = module
        self.connection = Connection(self.module._socket_path)

        if not_rest_data_keys:
            self.not_rest_data_keys = not_rest_data_keys
        else:
            self.not_rest_data_keys = []
        self.not_rest_data_keys.append("validate_certs")
        self.headers = headers

    def get(self, url):
        code, response = self.connection.send_request("GET", url, headers=self.headers)
        return response

    def put(self, url, data=None):
        code, response = self.connection.send_request(
            "PUT", url, data=data, headers=self.headers
        )
        return response

    def post(self, url, data=None):
        code, response = self.connection.send_request(
            "POST", url, data=data, headers=self.headers
        )
        return response

    def patch(self, url, data=None):
        code, response = self.connection.send_request(
            "PATCH", url, data=data, headers=self.headers
        )
        return response

    def delete(self, url, data=None):
        code, response = self.connection.send_request(
            "DELETE", url, data=data, headers=self.headers
        )
        return response

    def get_data(self):
        """
        Get the valid fields that should be passed to the REST API as urlencoded
        data so long as the argument specification to the module follows the
        convention:
            - the key to the argspec item does not start with qradar_
            - the key does not exist in the not_data_keys list
        """
        try:
            # FIXME
            pass

        except TypeError as e:
            self.module.fail_json(msg="invalid data type provided: {0}".format(e))

    def get_urlencoded_data(self):
        return urlencode(self.get_data())

    def get_by_path(self, rest_path):
        """
        GET attributes of a monitor by rest path
        """
        return self.get("/{0}".format(rest_path))

    def delete_by_path(self, rest_path):
        """
        DELETE attributes of a monitor by rest path
        """

        return self.delete("/{0}".format(rest_path))

    def post_by_path(self, rest_path, data=None):
        """
        POST with data to path
        """
        if data is None:
            data = json.dumps(self.get_data())
        elif data is False:
            return self.post("/{0}".format(rest_path))
        elif data:
            return self.post("/{0}".format(rest_path), data=json.dumps(data))
        return self.post("/{0}".format(rest_path), data=data)

    def create_update(self, rest_path, data=None):
        """
        Create or Update a file/directory monitor data input in qradar
        """
        if data is None:
            data = json.dumps(self.get_data())
        # return self.post("/{0}".format(rest_path), data=data)
        return self.patch("/{0}".format(rest_path), data=data)  # PATCH
