#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}
DOCUMENTATION = """
---
module: computers_info
short_description: Obtain information about Symantec Endpoint Protection Manager computers
description:
  - Obtain information about Symantec Endpoint Protection Manager computers
version_added: "2.9"
options:
  name:
    description:
     - The host name of computer. Wild card is supported as '*'.
    required: false
    type: str
  domain:
    description:
     - The domain from which to get computer information.
    required: false
    type: str
  mac:
    description:
     - The MAC address of computer. Wild card is supported as '*'.
    required: false
    type: str
  os:
    description:
     - The list of OS to filter.
    choices:
     - CentOs
     - Debian
     - Fedora
     - MacOSX
     - Oracle
     - OSX
     - RedHat
     - SUSE
     - Ubuntu
     - Win10
     - Win2K
     - Win7
     - Win8
     - Win81
     - WinEmb7
     - WinEmb8
     - WinEmb81
     - WinFundamental
     - WinNT
     - Win2K3
     - Win2K8
     - Win2K8R2
     - Win2K12
     - Win2K12R2
     - Win2K16
     - WinVista
     - WinXP
     - WinXPEmb
     - WinXPProf64
    required: false
    type: list
notes:
  - This module returns a dict of group data and is meant to be registered to a
    variable in a Play for conditional use or inspection/debug purposes.

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


RETURN = """
id_list:
    type: str
    returned: always
    description: comma separated list of computer ids
computers:
    type: list
    returned: always
    elements: dict
    description: Each list entry contains a dictionary that represents
                 a computer to Symantec Endpoint Security
                 https://apidocs.symantec.com/home/saep#_computer
"""

EXAMPLES = """
- name: get information about all computers
  computers_info:
  register: computers_info_out

# Display the values returned
- debug:
    var: computers_info_out

- name: get information about all computers in a specific domain running Win7 and/or WinXP
  symantec.epm.computers_info:
    domain: "723191A4AC10037351F18F7B0E549D59"
    os:
      - Win7
      - WinXP
  register: computers_info_out

# Display the values returned
- debug:
    var: computers_info_out

# Display only the id_list from values returned
- debug:
    var: computers_info_out['id_list']
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.symantec.epm.plugins.module_utils.sep_client import Sepclient

import copy
import json


def main():

    argspec = dict(
        name=dict(required=False, type="str"),
        domain=dict(required=False, type="str"),
        mac=dict(required=False, type="str"),
        os=dict(
            required=False,
            type="list",
            choices=[
                "CentOs",
                "Debian",
                "Fedora",
                "MacOSX",
                "Oracle",
                "OSX",
                "RedHat",
                "SUSE",
                "Ubuntu",
                "Win10",
                "Win2K",
                "Win7",
                "Win8",
                "Win81",
                "WinEmb7",
                "WinEmb8",
                "WinEmb81",
                "WinFundamental",
                "WinNT",
                "Win2K3",
                "Win2K8",
                "Win2K8R2",
                "Win2K12",
                "Win2K12R2",
                "Win2K16",
                "WinVista",
                "WinXP",
                "WinXPEmb",
                "WinXPProf64",
            ],
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    sclient = Sepclient(module)

    client_response = sclient.get_computers(
        computername=module.params["name"],
        domain=module.params["domain"],
        os=",".join(module.params["os"]) if module.params["os"] else module.params["os"],
    )

    if "content" in client_response:
        list_of_computers = client_response["content"]
        id_list = ""
        try:
            id_list += ",".join([comp["uniqueId"] for comp in list_of_computers])
        except KeyError:
            module.warn("Unable to compile id_list")
        module.exit_json(computers=list_of_computers, id_list=id_list, changed=False)
    else:
        module.fail_json(msg="Unable to query Computers data", sepm_data=client_response)


if __name__ == "__main__":
    main()
