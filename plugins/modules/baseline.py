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
module: baseline
short_description: Schedule an Baseline application information upload on the endpoint(s).
description:
  - Schedule an Baseline application information upload on the endpoint(s).
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
notes:
  - Module requires either C(computers) or C(groups) be provided, or both.
  - Because of the means of interaction with Symantec Endpoint Protection, this
    module is not idempotent. Every time this module is called via a task in a
    module a scan will be scheduled on the Endpoint Protection Manager.

author: "Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
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
# For more specific examples of symantec.epm.groups_info, please consult that
# module's documentation as it is only included here to demonstrate a common
# pattern of dynamically gathering input data for symantec.epm.baseline
- name: get all groups
  symantec.epm.groups_info:
  register: groups_info_out

- name: baseline scan all members of groups found from symantec.epm.groups_out
  symantec.epm.baseline:
    groups: "{{ groups_info_out['id_list'] }}"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible_collections.symantec.epm.plugins.module_utils.epm import EPMRequest


def main():

    argspec = dict(
        computers=dict(required=False, type="str"),
        groups=dict(required=False, type="str"),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        required_one_of=[["computers", "groups"]],
        supports_check_mode=False,
    )

    epm_request = EPMRequest(module, headers={"Content-Type": "application/json"})

    query_data = {}

    if module.params["computers"]:
        query_data["computer_ids"] = module.params["computers"]

    if module.params["groups"]:
        query_data["group_ids"] = module.params["groups"]

    sepm_data = epm_request.post_by_path(
        "sepm/api/v1/command-queue/baseline?{0}".format(urlencode(query_data)),
        data=False,
    )

    if "errorCode" in sepm_data:
        module.fail_json(
            msg="Failed to schedule Baseline Application Data Upload",
            sepm_data=sepm_data,
        )
    command_ids = []
    if 'commandID_computer' in sepm_data:
        command_ids.append(sepm_data['commandID_computer'])
    if 'commandID_group' in sepm_data:
        command_ids.append(sepm_data['commandID_group'])

    module.exit_json(sepm_data=sepm_data, command_ids=command_ids, changed=True)


if __name__ == "__main__":
    main()
