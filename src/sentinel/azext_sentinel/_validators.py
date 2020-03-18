# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from knack.util import CLIError


def detection_create_validator(namespace):
    if bool(namespace.detections_directory) == bool(namespace.detection_file):
        raise CLIError('incorrect usage: --detections-directory DIRECTORY | --detection-file FILE')


def detection_generate_validator(namespace):
    if bool(namespace.skip_interactive):
        if not bool(namespace.display_name):
            raise CLIError('incorrect usage: --display-name DETECTION_NAME')
