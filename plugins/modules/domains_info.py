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
module: domains_info
short_description: Obtain information about Symantec Endpoint Protection Manager domains
description:
  - Obtain information about Symantec Endpoint Protection Manager domains
options:
  domain:
    description:
      - The domain ID to get information about instead of all domains
    required: false
    type: str
version_added: "2.9"
notes:
  - This module does not take any options as input
  - This module returns a list of dicts of domain data and is meant to be
    registered to a variable in a Play for conditional use or inspection/debug
    purposes.

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


RETURN = """
id_list:
    type: str
    returned: always
    description: comma separated list of domain ids
domains:
    type: list
    returned: always
    elements: dict
    description: Each list entry contains a dictionary that represents
                 a domain to Symantec Endpoint Security
                 https://apidocs.symantec.com/home/saep#_domainaddeditto
"""

EXAMPLES = """
- name: get information about all domains
  symantec.epm.domains_info:
  register: domains_info_out

# Display the values returned
- debug:
    var: domains_info_out

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

    client_response = sclient.get_domains()

    list_of_domains = client_response
    id_list = ""
    try:
        id_list += ",".join([domain["id"] for domain in list_of_domains])
    except KeyError:
        module.warn("Unable to compile id_list")
    module.exit_json(domains=list_of_domains, id_list=id_list, changed=False)


if __name__ == "__main__":
    main()
