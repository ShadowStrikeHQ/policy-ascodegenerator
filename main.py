#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Dict, Any, List

import networkx as nx
import ipaddress
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the policy-AsCodeGenerator tool.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """

    parser = argparse.ArgumentParser(
        description="Generates security policy code from a high-level policy description."
    )

    parser.add_argument(
        "--policy_file",
        type=str,
        required=True,
        help="Path to the policy description file (e.g., YAML, JSON)."
    )

    parser.add_argument(
        "--template_dir",
        type=str,
        required=True,
        help="Path to the directory containing Jinja2 templates."
    )

    parser.add_argument(
        "--template_name",
        type=str,
        required=True,
        help="Name of the Jinja2 template to use (e.g., 'firewall.tf.j2')."
    )

    parser.add_argument(
        "--output_file",
        type=str,
        required=True,
        help="Path to the output file where the generated code will be written."
    )

    parser.add_argument(
        "--log_level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)."
    )

    return parser


def validate_policy_data(policy_data: Dict[str, Any]) -> None:
    """
    Validates the policy data to ensure it conforms to the expected structure and data types.

    Args:
        policy_data (Dict[str, Any]): The parsed policy data.

    Raises:
        ValueError: If the policy data is invalid.
    """
    if not isinstance(policy_data, dict):
        raise ValueError("Policy data must be a dictionary.")

    # Example validation:  Check for a required key and its type
    if "policy_name" not in policy_data:
        raise ValueError("Policy data must contain 'policy_name' key.")
    if not isinstance(policy_data["policy_name"], str):
        raise ValueError("'policy_name' must be a string.")

    if "rules" not in policy_data:
        raise ValueError("Policy data must contain 'rules' key")
    if not isinstance(policy_data["rules"], list):
        raise ValueError("'rules' must be a list")

    for rule in policy_data["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Each rule in 'rules' must be a dictionary.")

        if "source" not in rule:
            raise ValueError("Each rule must contain a 'source'")
        if "destination" not in rule:
            raise ValueError("Each rule must contain a 'destination'")
        if "ports" not in rule:
            raise ValueError("Each rule must contain a 'ports'")


def generate_code_from_template(template_dir: str, template_name: str, policy_data: Dict[str, Any]) -> str:
    """
    Generates security policy code from a Jinja2 template.

    Args:
        template_dir (str): Path to the directory containing the templates.
        template_name (str): Name of the template file.
        policy_data (Dict[str, Any]): The policy data to render into the template.

    Returns:
        str: The generated code.

    Raises:
        TemplateNotFound: If the specified template file is not found.
        Exception: For other template rendering errors.
    """
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template(template_name)
        code = template.render(policy_data)
        return code
    except TemplateNotFound:
        logging.error(f"Template file not found: {template_name}")
        raise
    except Exception as e:
        logging.error(f"Error rendering template: {e}")
        raise


def write_code_to_file(code: str, output_file: str) -> None:
    """
    Writes the generated code to the specified output file.

    Args:
        code (str): The generated code.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            f.write(code)
        logging.info(f"Generated code written to: {output_file}")
    except IOError as e:
        logging.error(f"Error writing to file: {e}")
        raise


def load_policy_data(policy_file: str) -> Dict[str, Any]:
    """
    Loads policy data from a file (e.g., YAML, JSON).  Currently, only JSON and YAML are supported
    and the function automatically detects the file type from the extension.

    Args:
        policy_file (str): Path to the policy file.

    Returns:
        Dict[str, Any]: The loaded policy data.

    Raises:
        ValueError: If the file format is not supported.
        FileNotFoundError: if the policy_file does not exist
        Exception: If an error occurs during loading.
    """
    import os
    if not os.path.exists(policy_file):
        raise FileNotFoundError(f"Policy file not found: {policy_file}")

    try:
        import json
        import yaml

        if policy_file.endswith(".json"):
            with open(policy_file, "r") as f:
                return json.load(f)
        elif policy_file.endswith(".yaml") or policy_file.endswith(".yml"):
            with open(policy_file, "r") as f:
                return yaml.safe_load(f)
        else:
            raise ValueError("Unsupported policy file format.  Must be JSON or YAML.")

    except ImportError as e:
        logging.error(f"Error importing required libraries: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading policy data: {e}")
        raise


def main() -> None:
    """
    Main function to orchestrate the policy-AsCode generation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)

    try:
        # 1. Load policy data
        policy_data = load_policy_data(args.policy_file)

        # 2. Validate policy data
        validate_policy_data(policy_data)

        # 3. Generate code from template
        code = generate_code_from_template(args.template_dir, args.template_name, policy_data)

        # 4. Write code to file
        write_code_to_file(code, args.output_file)

        logging.info("Policy-As-Code generation completed successfully.")

    except (ValueError, FileNotFoundError, TemplateNotFound) as e:
        logging.error(f"Error: {e}")
        sys.exit(1) # Non-zero exit code indicates failure
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        sys.exit(1)


if __name__ == "__main__":
    # Example usage:
    # python main.py --policy_file policy.yaml --template_dir templates --template_name firewall.tf.j2 --output_file firewall.tf
    main()