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
module: groups_info
short_description: Obtain information about Symantec Endpoint Protection Manager groups
description:
  - Obtain information about Symantec Endpoint Protection Manager groups
options:
  domain:
    description:
     - The domain from which to get group information.
    required: false
    type: str

version_added: "2.9"
notes:
  - This module returns a dict of group data and is meant to be registered to a
    variable in a Play for conditional use or inspection/debug purposes.

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""


RETURN = """
id_list:
    type: str
    returned: always
    description: comma separated list of group ids
groups:
    type: list
    returned: always
    elements: dict
    description: Each list entry contains a dictionary that represents
                 a group to Symantec Endpoint Security
                 https://apidocs.symantec.com/home/saep#_group
"""

EXAMPLES = """
- name: get information about all groups
  symantec.epm.groups_info:
  register: groups_info_out

# Display the values returned
- debug:
    var: groups_info_out

- name: get information about all groups belonging to a certain domain
  symantec.epm.groups_info:
    domain: "723191A4AC10037351F18F7B0E549D59"
  register: groups_in_domain_info_out

# Display the values returned
- debug:
    var: groups_in_domain_info_out

"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.symantec.epm.plugins.module_utils.sep_client import Sepclient

import copy
import json


def main():

    argspec = dict(domain=dict(required=False, type="str"),)

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    sclient = Sepclient(module)

    client_response = sclient.get_groups(domain=module.params["domain"],)

    if "content" in client_response:
        list_of_groups = client_response["content"]
        id_list = ""
        try:
            id_list += ",".join([group["id"] for group in list_of_groups])
        except KeyError:
            module.warn("Unable to compile id_list")
        module.exit_json(groups=list_of_groups, id_list=id_list, changed=False)
    else:
        module.fail_json(msg="Unable to query groups data")


if __name__ == "__main__":
    main()
