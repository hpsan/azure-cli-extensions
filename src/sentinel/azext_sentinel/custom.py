# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import uuid

from pathlib import Path
from typing import List, Union, Generator, Optional

import jsonschema
import yaml
from azure.cli.core.commands.client_factory import get_mgmt_service_client, get_subscription_id
from jsonschema import ValidationError
from knack.log import get_logger
from knack.prompting import prompt, prompt_y_n
from knack.util import CLIError

from .vendored_sdks.loganalytics.mgmt.loganalytics import LogAnalyticsManagementClient
from .vendored_sdks.loganalytics.mgmt.loganalytics.models import SavedSearch
from ._validators import validate_name
from .constants import ResourceType, RESOURCE_DEFAULTS, ResourceConfig, SENTINEL_POST_ALERT_TRIGGER_PATH, \
    ResourceFetchMethod
from .vendored_sdks.logic_app.mgmt.logic.logic_management_client import LogicManagementClient
from .vendored_sdks.security_insights import SecurityInsights
from .vendored_sdks.security_insights.models import AlertRule, ActionResponse, ActionRequest, ScheduledAlertRule

logger = get_logger(__name__)
DEFAULT_RESOURCE_PROVIDER = "Microsoft.OperationalInsights"
PARSER_CATEGORY_NAME = "parser"
SAVED_SEARCH_ID_TEMPLATE = "subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/savedSearches/{}"


def create_detections(
        cmd,
        client: SecurityInsights,
        resource_group_name: str,
        workspace_name: str,
        detections_directory: Optional[str] = None,
        detection_file: Optional[str] = None,
        detection_schema: Optional[str] = None,
        enable_validation: Optional[bool] = False
) -> List[AlertRule]:
    """Loads the detection config from the local file/dir, validates it and deploys it"""
    security_insights_client = client
    playbook_client: LogicManagementClient = get_mgmt_service_client(cmd.cli_ctx, LogicManagementClient)

    if enable_validation:
        validate_detections(detections_directory, detection_file, detection_schema)

    detection_files = _get_resource_files(detection_file, detections_directory)
    deployed_detections = []
    for file in detection_files:
        deployed_detections.append(
            _create_or_update_detection(
                security_insights_client, playbook_client, resource_group_name, workspace_name, file))
    return deployed_detections


def validate_detections(
        detections_directory: Optional[str] = None,
        detection_file: Optional[str] = None,
        detection_schema: Optional[str] = None
) -> None:
    """Validates the detections against its configured JSON schema"""
    validate_resources(
        resource_type=ResourceType.DETECTION,
        resources_directory=detections_directory,
        resource_file=detection_file,
        resource_schema=detection_schema
    )


def generate_detection(
        detections_directory: Optional[str] = None,
        skip_interactive: Optional[bool] = False,
        name: Optional[str] = None,
        create_directory: Optional[bool] = True,
        with_documentation: Optional[bool] = True,
):
    """Creates a scaffolding for the detection based on the configured template"""
    generate_resource(
        resource_type=ResourceType.DETECTION,
        resources_directory=detections_directory,
        skip_interactive=skip_interactive,
        name=name,
        create_directory=create_directory,
        with_documentation=with_documentation
    )


def create_data_sources(
        cmd,
        client: SecurityInsights,
        resource_group_name: str,
        workspace_name: str,
        data_sources_directory: Optional[str] = None,
        data_source_file: Optional[str] = None,
        data_source_schema: Optional[str] = None,
        enable_validation: Optional[bool] = False
) -> List[SavedSearch]:
    """
    Loads the data source config from the local file/dir, validates it and deploys it
    Note that at this point, it only deploys
    the parser associated with the data source and not other related entities such as data source connectors
    """
    security_insights_client = client
    loganalytics_client: LogAnalyticsManagementClient = get_mgmt_service_client(cmd.cli_ctx, LogAnalyticsManagementClient)
    subscription_id = get_subscription_id(cmd.cli_ctx)

    if enable_validation:
        validate_data_sources(data_sources_directory, data_source_file, data_source_schema)

    data_source_files = _get_resource_files(data_source_file, data_sources_directory)
    deployed_data_sources = []
    for file in data_source_files:
        deployed_data_source = _create_or_update_data_source(
            loganalytics_client, subscription_id, resource_group_name, workspace_name, file)
        if deployed_data_source:
            deployed_data_sources.append(deployed_data_source)
    return deployed_data_sources


def generate_data_source(
        data_sources_directory: Optional[str] = None,
        skip_interactive: Optional[bool] = False,
        name: Optional[str] = None,
        create_directory: Optional[bool] = True,
        with_documentation: Optional[bool] = True
):
    """Creates a scaffolding for the data source based on the configured template"""
    generate_resource(
        resource_type=ResourceType.DATA_SOURCE,
        resources_directory=data_sources_directory,
        skip_interactive=skip_interactive,
        name=name,
        create_directory=create_directory,
        with_documentation=with_documentation
    )


def generate_resource(
        resource_type: ResourceType,
        resources_directory: Optional[str] = None,
        skip_interactive: Optional[bool] = False,
        name: Optional[str] = None,
        create_directory: Optional[bool] = False,
        with_documentation: Optional[bool] = False,
) -> None:
    """Creates a scaffolding for the given resource based on the configured template"""
    # Populate values for the resource
    if not skip_interactive:
        if not name:
            name = prompt(f"Name your {resource_type.value}(alphanumeric without spaces): ")
            validate_name(name)
        if not create_directory:
            create_directory = prompt_y_n(
                f"Would you like to create a new directory for your {resource_type.value}?")
        if not with_documentation:
            with_documentation = prompt_y_n(
                f"Would you like to create a documentation file for your {resource_type.value}?")
    resources_directory: str = resources_directory if resources_directory else os.getcwd()
    resource_file_name: str = name + '.yaml'
    resource_template = _resolve_config_file(resource_type, ResourceConfig.TEMPLATE)
    resource_config: str = resource_template.read_text().format(unique_id=str(uuid.uuid4()), name=name)

    # Setup resource directory
    if create_directory:
        directory_path: Path = Path(resources_directory) / name
        directory_path.mkdir()
    else:
        directory_path: Path = Path(resources_directory)

    # Write resource
    resource_file: Path = directory_path / resource_file_name
    resource_file.write_text(resource_config)
    if with_documentation:
        resource_documentation = _resolve_config_file(resource_type, ResourceConfig.DOCUMENTATION)
        _create_documentation(resource_documentation, name, directory_path)


def validate_data_sources(
        data_sources_directory: Optional[str] = None,
        data_source_file: Optional[str] = None,
        data_source_schema: Optional[str] = None
):
    """Validates the data source against its configured JSON schema"""
    validate_resources(
        resource_type=ResourceType.DATA_SOURCE,
        resources_directory=data_sources_directory,
        resource_file=data_source_file,
        resource_schema=data_source_schema
    )


def validate_resources(
        resource_type: ResourceType,
        resources_directory: Optional[str] = None,
        resource_file: Optional[str] = None,
        resource_schema: Optional[str] = None,
) -> None:
    """Validates the given resources against its configured JSON schema"""
    # TODO: check if there are resources with the same ID

    resource_schema_file = _resolve_config_file(resource_type, ResourceConfig.SCHEMA, resource_schema)
    schema = yaml.safe_load(resource_schema_file.read_text())
    resource_files = _get_resource_files(resource_file, resources_directory)
    for file in resource_files:
        logger.info(f"Validating {resource_type.value} {file} with schema at {resource_schema_file}")
        alert_rule = yaml.safe_load(file.read_text())
        try:
            jsonschema.validate(alert_rule, schema)
        except ValidationError as validationError:
            raise CLIError(validationError.message)
    logger.info('All validations successful!')


def _resolve_config_file(
        resource_type: ResourceType,
        resource_config: ResourceConfig,
        preferred_config: Optional[str] = None
) -> Path:
    """
    Returns the most local config. If `preferred_config` is provided, it returns it.
    If not, looks for a local file. If that is not available, returns the config file bundled with the CLI
    """
    if preferred_config:
        config_file = Path(preferred_config)
    else:
        local_file = _get_local_config_file(resource_type, resource_config)
        fallback_file = RESOURCE_DEFAULTS[resource_type][resource_config][ResourceFetchMethod.FALLBACK]
        config_file = local_file if local_file else fallback_file
    return config_file


def _get_local_config_file(
        resource_type: ResourceType,
        resource_config: ResourceConfig
) -> Union[Path, None]:
    """Loads the local config file if available by traversing upto the HOME directory of the user"""
    file_name = RESOURCE_DEFAULTS[resource_type][resource_config][ResourceFetchMethod.LOCAL]
    current_path = Path.cwd()
    while current_path not in [Path.home(), current_path.root]:
        local_file = current_path / file_name
        if local_file.exists():
            return local_file
        else:
            current_path = current_path.parent
            continue
    return None


def _get_resource_files(
        resource_file: Optional[str] = None,
        resources_directory: Optional[str] = None
) -> Union[Generator[Path, None, None], List[Path]]:
    """ Gets all the YAML files in the folder or just returns the original file if `resource_file` is provided """
    if resources_directory:
        resource_path = Path(resources_directory)
        resource_files = resource_path.glob('**/*.yaml')
    else:
        resource_files = [Path(resource_file)]
    return resource_files

def _create_or_update_detection(
        security_insights_client: SecurityInsights,
        playbook_client: LogicManagementClient,
        resource_group_name: str,
        workspace_name: str,
        detection_file: Path
) -> AlertRule:
    """Loads the detection config from the local file/dir and deploys it"""
    alert_rule = yaml.safe_load(detection_file.read_text())
    alert_playbook_name = alert_rule.pop('playbook_name', None)
    alert_rule.pop('additional_metadata', None)
    # incident_configuration = alert_rule.pop('incident_configuration', None)
    # Fetch the existing rule to update if it already exists
    try:
        existing_rule = security_insights_client.alert_rules.get(resource_group_name,
                                                                 DEFAULT_RESOURCE_PROVIDER,
                                                                 workspace_name,
                                                                 alert_rule['id'])
        alert_rule['etag'] = existing_rule.etag
    except Exception:
        pass
    # Create the rule
    try:
        alert = ScheduledAlertRule(**alert_rule)
        created_alert: AlertRule = security_insights_client.alert_rules.create_or_update(
            resource_group_name,
            DEFAULT_RESOURCE_PROVIDER,
            workspace_name,
            alert_rule['id'],
            alert)
    except Exception as azCloudError:
        logger.error('Unable to create/update the detection %s due to %s', detection_file, str(azCloudError))
        raise azCloudError
    # Link the playbook if it is configured
    if alert_playbook_name:
        _link_playbook(
            security_insights_client,
            playbook_client,
            resource_group_name,
            workspace_name,
            alert_rule['id'],
            alert_playbook_name
        )
    else:
        _unlink_all_playbooks(
            security_insights_client,
            resource_group_name,
            workspace_name,
            alert_rule['id']
        )

    return created_alert


def _link_playbook(
        security_insights_client: SecurityInsights,
        playbook_client: LogicManagementClient,
        resource_group_name: str,
        workspace_name: str,
        rule_id: str,
        playbook_name: str
) -> ActionResponse:
    previously_linked_playbooks: List[ActionResponse] = security_insights_client.actions.list_by_alert_rule(
        resource_group_name,
        DEFAULT_RESOURCE_PROVIDER,
        workspace_name,
        rule_id
    ).value
    if len(previously_linked_playbooks) == 1 and previously_linked_playbooks[0].name == playbook_name:
        linked_playbook: ActionResponse = previously_linked_playbooks[0]
    else:
        _unlink_all_playbooks(security_insights_client, resource_group_name, workspace_name, rule_id)
        playbook = playbook_client.workflows.get(resource_group_name, playbook_name)
        trigger_uri = playbook.access_endpoint + SENTINEL_POST_ALERT_TRIGGER_PATH
        action_request = ActionRequest(
            logic_app_resource_id=playbook.id,
            trigger_uri=trigger_uri,
        )
        linked_playbook = security_insights_client.alert_rules.create_or_update_action(
            resource_group_name,
            DEFAULT_RESOURCE_PROVIDER,
            workspace_name,
            rule_id,
            playbook_name,
            action_request
        )
        return linked_playbook


def _unlink_all_playbooks(
        security_insights_client: SecurityInsights,
        resource_group_name: str,
        workspace_name: str,
        rule_id: str
):
    linked_playbooks: List[ActionResponse] = security_insights_client.actions.list_by_alert_rule(
        resource_group_name,
        DEFAULT_RESOURCE_PROVIDER,
        workspace_name,
        rule_id
    ).value
    for linked_playbook in linked_playbooks:
        security_insights_client.alert_rules.delete_action(
            resource_group_name,
            workspace_name,
            rule_id,
            linked_playbook.name
        )
    return


def _create_or_update_data_source(
        loganalytics_client: LogAnalyticsManagementClient,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
        data_source_file: Path
) -> Optional[SavedSearch]:
    """
    Loads the data soure config from the local file/dir and deploys it. Note that at this point, it only deploys
    the parser associated with the data source and not other related entities such as data source connectors
    """
    data_source = yaml.safe_load(data_source_file.read_text())
    parser = data_source.get('parser')
    if not parser:
        return None
    # Fetch the existing parser to update if it already exists
    try:
        existing_parser: SavedSearch = loganalytics_client.saved_searches.get(resource_group_name,
                                                                              workspace_name,
                                                                              parser['function_id'])
        parser['etag'] = existing_parser.additional_properties['etag']
    except Exception:
        pass
    try:
        saved_search = SavedSearch(
            id=SAVED_SEARCH_ID_TEMPLATE.format(
                subscription_id,
                resource_group_name,
                workspace_name,
                parser['function_id']
            ),
            display_name=parser['display_name'],
            function_alias=parser['display_name'],
            query=parser['query'],
            e_tag=parser.get('etag'),
            category=PARSER_CATEGORY_NAME
        )
        created_saved_search: SavedSearch = loganalytics_client.saved_searches.create_or_update(
            resource_group_name, workspace_name, parser['function_id'], saved_search
        )
    except Exception as azCloudError:
        logger.error('Unable to create/update the parser %s due to %s', data_source_file, str(azCloudError))
        raise azCloudError
    return created_saved_search


def _create_documentation(
        documentation_template: Path,
        detection_name: str,
        documentation_location: Path
) -> None:
    documentation_template_content: str = documentation_template.read_text()
    documentation_content: str = "# {} \n \n".format(detection_name) + documentation_template_content
    documentation_file: Path = documentation_location / (detection_name + '.md')
    documentation_file.write_text(documentation_content)
