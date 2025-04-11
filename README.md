# policy-AsCodeGenerator
Generates security policy code (e.g., Terraform, Ansible) from a high-level, human-readable policy description using a template engine like Jinja2. Supports multiple policy formats and target platforms. - Focused on Defines and enforces security policies related to network connectivity and access control lists. Validates existing firewall rules and network configurations against these policies, highlighting deviations and potential security risks. 'networkx' for representing network topologies and 'ipaddress' for IP address manipulation.

## Install
`git clone https://github.com/ShadowStrikeHQ/policy-ascodegenerator`

## Usage
`./policy-ascodegenerator [params]`

## Parameters
- `-h`: Show help message and exit
- `--policy_file`: No description provided
- `--template_dir`: Path to the directory containing Jinja2 templates.
- `--template_name`: Name of the Jinja2 template to use (e.g., 
- `--output_file`: Path to the output file where the generated code will be written.
- `--log_level`: No description provided

## License
Copyright (c) ShadowStrikeHQ
