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
module: quarantine_endpoints
short_description: Quarantine Endpoints in a Symantec Endpoint Protection (SEP) environment
description:
  - Quarantine Endpoints in a Symantec Endpoint Protection (SEP) environment
version_added: "2.9"
options:
  computers:
    description:
     - Comma delimited list of computers to run the scan against
    required: false
    type: str
  groups:
    description:
     - Comma delimited list of groups to run the scan against
    required: false
    type: str
  quarantine:
    description:
     - To set an endpoint or set of endpoints quarantined(C(True)) or not quarentined (C(False)).
    type: bool
    required: false
    default: true
notes:
  - Must provide one of C(computers) or C(groups), or both parameters as input to this module.
  - Because of the means of interaction with Symantec Endpoint Protection, this
    module is not idempotent. Every time this module is called via a task in a
    module a quarantine action will be scheduled on the Endpoint Protection Manager.

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


# FIXME - provide correct example here
RETURN = """
sepm_data:
    description: Data returned from Symantec Endpoint Protection Manager
    returned: always
    type: complex
    contains:
        commandID_computer:
            description: Command ID from Symantec Endpoint Protection Manager
                         for the computer scheduled command
            returned: when C(computers) provided
            type: str
        commandID_group:
            description: Command ID from Symantec Endpoint Protection Manager
                         for the computer scheduled command
            returned: when C(groups) provided
            type: str
command_ids:
    description: List of all commandIDs spawned from this job
    returned: always
    type: list
"""

EXAMPLES = """
# For more specific examples of symantec.epm.computers_info, please consult that
# module's documentation as it is only included here to demonstrate a common
# pattern of dynamically gathering input data for symantec.epm.quarantine_endpoints
- name: get all computers running Win7
  symantec.epm.computers_info:
  register: computers_info_out

- name: quarantine computers found to still be running win7 from symantec.epm.computers_info
  symantec.epm.quarantine_endpoints:
    computers: "{{ computerss_info_out['id_list'] }}"

"""

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible_collections.symantec.epm.plugins.module_utils.sep_client import Sepclient


def main():

    argspec = dict(
        computers=dict(required=False, type="str"),
        groups=dict(required=False, type="str"),
        quarantine=dict(required=False, type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        required_one_of=[["computers", "groups"]],
        supports_check_mode=False,
    )

    sclient = Sepclient(module)

    # Need a little book keeping for the IBM SEP Client API expectations
    if module.params["quarantine"] is False:
        undo = True
    else:
        undo = None

    sepm_data = sclient.quarantine_endpoints(
        computer_ids=module.params["computers"],
        group_ids=module.params["groups"],
        undo=undo,
    )

    if "errorCode" in sepm_data:
        module.fail_json(msg="Failed to qaurantine.", sepm_data=sepm_data)

    command_ids = []
    if 'commandID_computer' in sepm_data:
        command_ids.append(sepm_data['commandID_computer'])
    if 'commandID_group' in sepm_data:
        command_ids.append(sepm_data['commandID_group'])

    module.exit_json(sepm_data=sepm_data, command_ids=command_ids, changed=True)


if __name__ == "__main__":
    main()
