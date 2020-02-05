# Symantec Endpoint Protection Manager

## Tech Preview

This is the [Ansible
Collection](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
provided by the [Ansible Security Automation
Team](https://github.com/ansible-security) for automating actions in [Symantec
Endpoint Protection Manager](https://www.symantec.com/products/endpoint).

This Collection is meant for distribution via
[Ansible Galaxy](https://galaxy.ansible.com/) as is available for all
[Ansible](https://github.com/ansible/ansible) users to utilize, contribute to,
and provide feedback about.

### Using Symantec Endpoint Protection Manager Collection

An example for using this collection to manage
[Symantec Endpoint Protection Manager](https://www.symantec.com/products/endpoint)
is as follows.

`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.
```
[epm]
epm.example.com

[epm:vars]
ansible_connection=httpapi
ansible_network_os=symantec.epm.epm
ansible_user=Admin
ansible_httpapi_pass=SuperSekretPassword
ansible_httpapi_port=8446
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=yes
```

Alternatively this can be done with an authentication token. (FIXME - TODO)


`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.
```
[epm]
epm.example.com

[epm:vars]
ansible_network_os=symantec.epm.epm
ansible_user=admin
ansible_httpapi_pass=SuperSekretPassword
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=yes
ansible_connection=httpapi
```

#### Using the modules with Fully Qualified Collection Name (FQCN)

With [Ansible
Collections](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
there are various ways to utilize them either by calling specific Content from
the Collection, such as a module, by it's Fully Qualified Collection Name (FQCN)
as we'll show in this example or by defining a Collection Search Path as the
examples below will display. **Note that this is the recommended method.**

`epm_with_collections_example.yml`
```
---
- name: Start baseline scan and quarantine old versions of Windows
  hosts: epm
  tasks:
    - name: get computers
      symantec.epm.computers_info:
      register: computers_info_out

    - name: start a baseline scan
      symantec.epm.baseline:
        computers: "{{ computers_info_out['id_list'] }}"

    - name: get all computers still running Windows XP or Windows 7
      symantec.epm.computers_info:
        os:
          - "Win7"
          - "WinXP"
      register: legacy_windows_computer_info_out

    - name: quarantine all legacy EOL versions of Windows
      symantec.epm.quarantine_endpoints:
        computers: "{{ legacy_windows_computer_info_out['id_list'] }}"
      when: legacy_windows_computer_info_out['id_list']|length > 0

```

#### Define your collection search path at the Play level

Below we specify our collection at the
[Play](https://docs.ansible.com/ansible/latest/user_guide/playbooks_intro.html)
level which allows us to use the `symantec.epm` modules without
the need for the FQCN for each task.

`epm_with_collections_example.yml`
```
---
- name: Start baseline scan and quarantine old versions of Windows
  hosts: epm
  collections: symantec.epm
  tasks:
    - name: get computers
      computers_info:
      register: computers_info_out

    - name: start a baseline scan
      baseline:
        computers: "{{ computers_info_out['id_list'] }}"

    - name: get all computers still running Windows XP or Windows 7
      computers_info:
        os:
          - "Win7"
          - "WinXP"
      register: legacy_windows_computer_info_out

    - name: quarantine all legacy EOL versions of Windows
      quarantine_endpoints:
        computers: "{{ legacy_windows_computer_info_out['id_list'] }}"
      when: legacy_windows_computer_info_out['id_list']|length > 0

```

#### Define your collection search path at the Block level

Another option for Collection use is below. Here we use the
[`block`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_blocks.html)
level keyword instead of [Play](https://docs.ansible.com/ansible/latest/user_guide/playbooks_intro.html)
level as with the previous example. In this scenario we are able to use the
`symantec.epm` modules without the need for the FQCN for each
task but with an optionally more specific scope of Collection Search Path than
specifying at the Play level.

`epm_with_collections_block_example.yml`
```
- name: Start baseline scan and quarantine old versions of Windows
  hosts: epm
  tasks:
    - name: run collection scope in a block
      collections:
        - symantec.epm
      block:
        - name: get computers
          computers_info:
          register: computers_info_out

        - name: start a baseline scan
          baseline:
            computers: "{{ computers_info_out['id_list'] }}"

        - name: get all computers still running Windows XP or Windows 7
          computers_info:
            os:
              - "Win7"
              - "WinXP"
          register: legacy_windows_computer_info_out

        - name: quarantine all legacy EOL versions of Windows
          quarantine_endpoints:
            computers: "{{ legacy_windows_computer_info_out['id_list'] }}"
          when: legacy_windows_computer_info_out['id_list']|length > 0

```
