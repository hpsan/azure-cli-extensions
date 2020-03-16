# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from pathlib import Path

import yaml
import jsonschema
from msrestazure.azure_exceptions import CloudError

from .vendored_sdks.models import ScheduledAlertRule

DEFAULT_DETECTION_SCHEMA = Path(__file__).parent / 'default_detection_schema.yaml'


def create_detection(cmd, client, resource_group_name, workspace_name, detections_folder=None, detection_schema=None,
                     enable_validation=False):
    if enable_validation:
        validate_detection(detections_folder, detection_schema)
    detection_path = Path(detections_folder)
    detection_files = detection_path.glob('**/*.yaml')
    for detection_file in detection_files:
        with open(detection_file, 'r') as detection_file_stream:
            alert_rule = yaml.safe_load(detection_file_stream)
            try:
                existing_rule = client.alert_rules.get(resource_group_name,
                                                       workspace_name,
                                                       alert_rule['id'])
                alert_rule['etag'] = existing_rule.etag
            except CloudError:
                pass
            alert = ScheduledAlertRule(**alert_rule)
            created_rule = client.alert_rules.create_or_update(
                resource_group_name,
                workspace_name,
                alert_rule['id'],
                alert)
    return client.alert_rules.list(resource_group_name=resource_group_name, workspace_name=workspace_name)


def validate_detection(detections_folder=None,
                       detection_schema=None):
    detection_path = Path(detections_folder)
    detection_files = detection_path.glob('**/*.yaml')

    detection_schema_file = detection_schema if detection_schema else DEFAULT_DETECTION_SCHEMA
    with open(detection_schema_file, 'r') as detection_schema_stream:
        schema = yaml.safe_load(detection_schema_stream)
        for detection_file in detection_files:
            with open(detection_file, 'r') as detection_file_stream:
                alert_rule = yaml.safe_load(detection_file_stream)
                jsonschema.validate(schema, alert_rule)
    print('Successfully Validated!')


def list_detections(cmd, client, resource_group_name, workspace_name):
    return client.alert_rules.list(resource_group_name=resource_group_name, workspace_name=workspace_name)


def delete_detection(cmd, client, resource_group_name, workspace_name, detection_id):
    client.alert_rules.delete()
    pass


def get_detection():
    pass
