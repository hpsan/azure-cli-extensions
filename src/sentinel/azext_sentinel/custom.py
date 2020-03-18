# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import uuid
from pathlib import Path
from typing import List, Union, Generator

import yaml
import jsonschema
from azext_sentinel.vendored_sdks.models import AlertRule
from azext_sentinel.vendored_sdks.operations import AlertRulesOperations

from .constants import DEFAULT_DETECTION_SCHEMA, DOCUMENTATION_TEMPLATE, DEFAULT_DETECTION_TEMPLATE
from knack.log import get_logger
from knack.prompting import prompt, prompt_y_n
from msrestazure.azure_exceptions import CloudError

from .vendored_sdks.models import ScheduledAlertRule

logger = get_logger(__name__)


def create_detections(
        cmd,  # pylint: disable=unused-argument
        client: AlertRulesOperations,
        resource_group_name: str,
        workspace_name: str,
        detections_directory: Union[str, None] = None,
        detection_file: Union[str, None] = None,
        detection_schema: Union[str, None] = None,
        enable_validation: bool = False
) -> List[AlertRule]:
    if enable_validation:
        validate_detections(detections_directory, detection_schema)
    detection_files = _get_detection_files(detection_file, detections_directory)
    deployed_detections = []

    for file in detection_files:
        deployed_detections.append(
            _create_or_update_detection(client, resource_group_name, workspace_name, file))
    return deployed_detections


def validate_detections(
        detections_directory: Union[str, None] = None,
        detection_file: Union[str, None] = None,
        detection_schema: Union[str, None] = None
) -> None:
    detection_schema_file = detection_schema if detection_schema else DEFAULT_DETECTION_SCHEMA
    schema = yaml.safe_load(detection_schema_file.read_text())
    detection_files = _get_detection_files(detection_file, detections_directory)
    for file in detection_files:
        logger.info('Validating detection %s with schema at %s', file, detection_schema_file)
        alert_rule = yaml.safe_load(file.read_text())
        jsonschema.validate(alert_rule, schema)
    logger.info('All validations successful!')


def generate_detection(
        detections_directory: Union[str, None] = None,
        skip_interactive: bool = False,
        name: Union[str, None] = None,
        create_directory: bool = True,
        with_documentation: bool = True
) -> None:
    # Populate values for the detection
    if not skip_interactive:
        if not name:
            name = prompt("Name your detection: ")
        if not create_directory:
            create_directory = prompt_y_n("Would you like to create a new directory for your detection?")
        if not with_documentation:
            with_documentation = prompt_y_n("Would you like to create a documentation file for your detection?")
    detections_directory: str = detections_directory if detections_directory else os.getcwd()
    detection_file_name: str = name + '.yaml'
    detection_config: str = DEFAULT_DETECTION_TEMPLATE.format(str(uuid.uuid4()), name, name)

    # Setup detection directory
    if create_directory:
        directory_path: Path = Path(detections_directory) / name
        directory_path.mkdir()
    else:
        directory_path: Path = Path(detections_directory)

    # Write Detection
    detection_file: Path = directory_path / detection_file_name
    detection_file.write_text(detection_config)
    if with_documentation:
        _create_documentation(DOCUMENTATION_TEMPLATE, name, directory_path)


def _get_detection_files(
        detection_file: Union[str, None] = None,
        detections_directory: Union[str, None] = None
) -> Union[Generator[Path, None, None], List[Path]]:
    if detections_directory:
        detection_path = Path(detections_directory)
        detection_files = detection_path.glob('**/*.yaml')
    else:
        detection_files = [Path(detection_file)]
    return detection_files


def _create_or_update_detection(
        client: AlertRulesOperations,
        resource_group_name: str,
        workspace_name: str,
        detection_file: Path
) -> Union[AlertRule, None]:
    alert_rule = yaml.safe_load(detection_file.read_text())
    # Fetch the existing rule to update if it already exists
    try:
        existing_rule = client.get(resource_group_name,
                                   workspace_name,
                                   alert_rule['id'])
        alert_rule['etag'] = existing_rule.etag
    except CloudError:
        pass
    try:
        alert = ScheduledAlertRule(**alert_rule)
        created_alert: Union[AlertRule, None] = client.create_or_update(
            resource_group_name,
            workspace_name,
            alert_rule['id'],
            alert)
    except CloudError as azCloudError:
        created_alert = None
        logger.error('Unable to create/update the detection %s due to %s', detection_file, str(azCloudError))
    return created_alert


def _create_documentation(
        documentation_template: Path,
        detection_name: str,
        documentation_location: Path
) -> None:
    documentation_template_content: str = documentation_template.read_text()
    documentation_content: str = "# {} \n \n".format(detection_name) + documentation_template_content
    documentation_file: Path = documentation_location / (detection_name + '.md')
    documentation_file.write_text(documentation_content)
