# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import re

from knack.util import CLIError

ALPHANUMERIC_REGEX = "^[a-zA-Z0-9-]*$"  # Dashes also allowed for historic reasons


def resource_create_validator(namespace):
    if bool(namespace.resources_directory) == bool(namespace.resource_file):
        raise CLIError(
            "incorrect usage: --resources-directory DIRECTORY | --resource-file FILE"
        )


def generate_validator(namespace):
    if bool(namespace.skip_interactive):
        validate_name(namespace.name)


def validate_name(name: str):
    if not (bool(name) and re.match(ALPHANUMERIC_REGEX, name)):
        raise CLIError("incorrect usage: --name NAME(alphanumeric without spaces)")
