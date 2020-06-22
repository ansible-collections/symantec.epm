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
module: command_status
short_description: Obtain information about Symantec Endpoint Protection Manager computers
description:
  - Obtain information about Symantec Endpoint Protection Manager computers
version_added: "2.9"
options:
  id:
    description:
     - The Symantec EPM Command Queue job id
    required: true
    type: str

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
# Using command_status to check on a quarantine command queue status
- name: quarantine an endpoint
  quarantine_endpoints:
    computers: "C6CDFF69AC10128F4FBB650B4A844722"
  register: quarantine_output

- name: check on the command status of all jobs created
  command_status:
    id: "{{ qaurantine_output['sepm_data']['commandID_computer'] }}"
  register: command_status_out

# Display the information returned
- debug:
    var: command_status_out

# Check status of all command queue ids
- name: check on the command status of all jobs created
  command_status:
    id: "{{ item }}"
  loop: "{{ quarantine_output['command_ids'] }}"
  register: command_status_out_list

# Display the information returned (will be a list of results)
- debug:
    var: command_status_out_list
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
        id=dict(required=True, type="str"),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    sclient = Sepclient(module)

    sepm_data = sclient.get_command_status(commandid=module.params['id'])

    module.exit_json(sepm_data=sepm_data, changed=False)
    # module.fail_json(msg="Unable to query Computers data", sepm_data=sepm_data)


if __name__ == "__main__":
    main()
