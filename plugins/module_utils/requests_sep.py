# -*- coding: utf-8 -*-
# (c) Copyright IBM Corp. 2019. All Rights Reserved.
# pragma pylint: disable=unused-argument, no-self-use
#
# Copyright © IBM Corporation 2010, 2019
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVßIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT ßOR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
#
# SPDX-License-Identifier:  MIT
#
# This code is based on code originally written by the IBM Resilient Team
# as attributed above. Original code can be found here:
#
#   https://github.com/ibmresilient/resilient-community-apps/tree/master/fn_sep
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

""" Process https requests """
import logging
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from io import BytesIO
from sys import version_info
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.symantec.epm.plugins.module_utils.epm import EPMRequest
from ansible.module_utils.connection import Connection
import json

# Magic number for zip file
ZIP_MAGIC = b"\x50\x4b\x03\x04"
# Hash lengths: SHA256 = 64, SHA-1 = 40, MD5 = 32
HASH_LENGTHS = [64, 40, 32]


class RequestsSep(object):
    """
    The class will be used to manage REST calls.

    """

    def __init__(self, module, sep_base_path):
        self.base_path = sep_base_path

        self.module = module

    def execute_call(self, verb, url, params=None, data=None, headers=None):
        """Method which initiates the REST API call. Default method is the GET method also supports POST, PATCH,
        PUT, DELETE AND HEAD. Retries are attempted if a Rate limit exception (429) is  detected.

        :param verb: GET, HEAD, PATCH, POST, PUT, DELETE
        :param url: Used to form url
        :param params: Parameters used by session request to form finished request
        :param data: Data body used in post requests
        :return: Response in json format

        """

        if verb.upper() in ["GET", "HEAD", "PATCH", "POST", "PUT", "DELETE"]:
            try:
                connection = Connection(self.module._socket_path)
                code, response = connection.send_request(
                    verb.upper(), url, headers=headers, params=params, data=data
                )

            except HTTPError as e:
                if (
                    e.code == 410
                    and verb.upper() in ["GET", "DELETE"]
                    and re.match(
                        "^https://.*"
                        + self.base_path
                        + "/policy-objects/fingerprints.*$",
                        url,
                    )
                ):
                    # We are probably trying to access/delete fingerprint list which doesn't exist.
                    self.module.fail_json(
                        msg="Got '410' error, possible attempt to '%s' a fingerprint list which doesn't exist."
                        % verb
                    )

                    # Allow error to bubble up to the Resilient function.
                elif (
                    e.code == 400
                    and verb.upper() in ["PUT"]
                    and re.match(
                        "^https://.*"
                        + self.base_path
                        + "/groups/.*/system-lockdown/fingerprints/.*$",
                        url,
                    )
                ):
                    # We are probably trying to re-add a hash to fingerprint list which already exists.
                    self.module.fail_json(
                        msg="Got '400' error, possible attempt to access a fingerprint list which doesn't exist."
                    )
                    # Allow error to bubble up to the Resilient function.
                elif (
                    e.code == 409
                    and verb.upper() in ["POST"]
                    and re.match(
                        "^https://.*"
                        + self.base_path
                        + "/policy-objects/fingerprints.*$",
                        url,
                    )
                ):
                    # We are probably trying to re-add a hash to fingerprint list which already exists.
                    self.module.fail_json(
                        msg="Got '409' error, possible attempt to re-add a hash to a fingerprint list."
                    )
                    # Allow error to bubble up to the Resilient function.
                else:
                    self.module.fail_json(msg="Uncaught exception: {0}".format(e))
        else:
            self.module.fail_json(
                msg="Unsupported request method '{0}'. This is probably a bug".format(
                    verb
                )
            )

        #  Firstly check if a zip file is returned.
        key = content = None
        # FIXME - Not sure if we need this, need to verify that the httpapi
        #         and Ansible urls lib handles it
        # if response.startswith(ZIP_MAGIC):
        #    (key, content) = self.get_unzipped_contents(self.module, r.content)
        #    return self.decrypt_xor(content, key)
        return response

    @staticmethod
    def get_unzipped_contents(module, content):
        """ Unzip file content zip file returned in response.
        Response zip will have contents as follows:

            |- <file with hash (sha256) as name>
            |- metadata.xml

        :param content: Response content.
        :return: Tuple with Unzipped file with hash as name and key.
        """
        key = c_unzipped = meta = None
        try:
            with ZipFile(BytesIO(content), "r") as zfile:
                for zip_file_name in zfile.namelist():
                    if (
                        len(zip_file_name) in HASH_LENGTHS
                        or zip_file_name == "metadata.xml"
                    ):
                        f = zfile.open(zip_file_name)
                        if len(zip_file_name) in HASH_LENGTHS:
                            # Get the hash file name.
                            c_unzipped = f.read()
                        elif zip_file_name == "metadata.xml":
                            # Get the key.
                            if version_info.major == 3:
                                meta = ET.fromstring(f.read())
                            else:
                                meta = ET.fromstring(f.read().encode("utf8", "ignore"))
                            for item in meta.findall("File"):
                                key = item.attrib["Key"]
                    else:
                        module.fail_json(
                            msg="Unknown hash type or key for zipfile contents: %s"
                            % zip_file_name
                        )
            return (key, c_unzipped)

        except ET.ParseError as e:
            module.fail_json(
                msg="During metadata file XML processing, Got exception type: %s, msg: %s"
                % (e.__repr__(), e.message)
            )

    @staticmethod
    def decrypt_xor(data, key):
        """ Unencrypt XORed data.

        :param data: XORed zip file data.
        :return: Unencrypted data.
        """
        data = bytearray(data)
        for i in range(len(data)):
            data[i] ^= int(key)
        return data
