# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import uuid
from pathlib import Path

import yaml
import jsonschema
from .constants import DEFAULT_DETECTION_SCHEMA, DOCUMENTATION_TEMPLATE, DEFAULT_DETECTION_TEMPLATE
from knack.log import get_logger
from knack.prompting import prompt, prompt_y_n
from msrestazure.azure_exceptions import CloudError

from .vendored_sdks.models import ScheduledAlertRule

logger = get_logger(__name__)


def create_detections(cmd, client, resource_group_name, workspace_name,  # pylint: disable=unused-argument
                      detections_directory=None, detection_file=None, detection_schema=None, enable_validation=False):
    if enable_validation:
        validate_detections(detections_directory, detection_schema)
    detection_files = _get_detection_files(detection_file, detections_directory)
    deployed_detections = []
    for detection_file in detection_files:
        deployed_detections.append(
            _create_or_update_detection(client, resource_group_name, workspace_name, detection_file))
    return deployed_detections


def validate_detections(detections_directory=None, detection_file=None, detection_schema=None):
    detection_schema_file = detection_schema if detection_schema else DEFAULT_DETECTION_SCHEMA
    with open(detection_schema_file, 'r') as detection_schema_stream:
        schema = yaml.safe_load(detection_schema_stream)
        detection_files = _get_detection_files(detection_file, detections_directory)
        for detection_file in detection_files:
            logger.info('Validating detection %s with schema at %s', detection_file, detection_schema_file)
            with open(detection_file, 'r') as detection_file_stream:
                alert_rule = yaml.safe_load(detection_file_stream)
                jsonschema.validate(schema, alert_rule)
    logger.info('All validations successful!')


def generate_detection(detections_directory=None,
                       interactive=False,
                       display_name=None,
                       create_directory=None,
                       with_documentation=None):
    if interactive:
        if not display_name:
            display_name = prompt("What is the name of the detection? ")
        if not create_directory:
            create_directory = prompt_y_n("Do you want to create a new directory for your detection?")
        if not with_documentation:
            with_documentation = prompt_y_n("Do you want to create a documentation file for your detection?")
    detections_directory = detections_directory if detections_directory else os.getcwd()
    detection_file_name = display_name + '.yaml'
    detection_config = DEFAULT_DETECTION_TEMPLATE.format(str(uuid.uuid4()), display_name, display_name)
    # Setup detection directory
    directory_path = None
    if create_directory:
        directory_path = Path(detections_directory) / display_name
        directory_path.mkdir()
    else:
        directory_path = Path(detections_directory)

    # Write Detection
    detection_file = directory_path / detection_file_name
    with open(detection_file, 'w') as detection_file_stream:
        detection_file_stream.write(detection_config)
    if with_documentation:
        _create_documentation(DOCUMENTATION_TEMPLATE, display_name, directory_path)


def _get_detection_files(detection_file=None, detections_directory=None):
    if detections_directory:
        detection_path = Path(detections_directory)
        detection_files = detection_path.glob('**/*.yaml')
    else:
        detection_files = [detection_file]
    return detection_files


def _create_or_update_detection(client, resource_group_name, workspace_name, detection_file):
    with open(detection_file, 'r') as detection_file_stream:
        alert_rule = yaml.safe_load(detection_file_stream)
        try:
            existing_rule = client.alert_rules.get(resource_group_name,
                                                   workspace_name,
                                                   alert_rule['id'])
            alert_rule['etag'] = existing_rule.etag
            alert = ScheduledAlertRule(**alert_rule)
            created_alert = client.alert_rules.create_or_update(
                resource_group_name,
                workspace_name,
                alert_rule['id'],
                alert)
        except CloudError as azCloudError:
            created_alert = None
            logger.error('Unable to create/update the detection %s due to %s', detection_file, str(azCloudError))
        return created_alert


def _create_documentation(documentation_template, detection_name, documentation_location):
    with open(documentation_template) as documentation_template_stream:
        documentation_template_content = documentation_template_stream.read()
        documentation_content = "# {} \n \n".format(detection_name) + documentation_template_content
        documentation_file = documentation_location / 'documentation.md'
        with open(documentation_file, 'w') as documentation_file_stream:
            documentation_file_stream.write(documentation_content)