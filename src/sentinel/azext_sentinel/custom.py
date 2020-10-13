# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import uuid
import jsonschema
import yaml


from pathlib import Path
from typing import List, Union, Generator, Optional, cast
from jsonschema import ValidationError
from knack.log import get_logger
from knack.prompting import prompt, prompt_y_n
from knack.util import CLIError

from msrest.serialization import Model
from msrest.pipeline import ClientRawResponse
from .vendored_sdks.loganalytics.mgmt.loganalytics.models import SavedSearch
from .vendored_sdks.security_insights.models import (
    AlertRule,
    ActionResponse,
)

from ._validators import validate_name
from .clients import (
    BaseClient,
    SecurityClient,
    AnalyticsClient,
    MultiTenantSecurityClient,
    client_factory,
)
from .constants import (
    ETAG_KEY,
    OperationType,
    ResourceType,
    RESOURCE_DEFAULTS,
    ResourceConfig,
    ResourceFetchMethod,
)
from .custom_models import (
    ResourceParams,
    ParserParams,
    DetectionParams,
    ScheduledDetectionParams,
    MicrosoftSecurityDetectionParams,
    PlaybookInfo,
    resource_params_factory,
)

logger = get_logger(__name__)

PLAYBOOK_NAME_KEY = "playbook_name"
ADDITIONAL_METADATA_KEY = "additional_metadata"
ID_KEY = "id"
FUNCTION_ID_KEY = "function_id"
DISPLAY_NAME_KEY = "display_name"
QUERY_KEY = "query"

def _convert_resource_type_enum(resource_type: str) -> ResourceType:
    try:
        return ResourceType(resource_type)
    except Exception as e:
        raise ValueError(
            "Supported resource types are scheduled_detection, microsoft_security_detection, and data_source"
        ) from e


def create_resources(
    cmd,
    resource_type: str,
    resource_group_name: str,
    workspace_name: str,
    enable_validation: bool = False,
    aux_subscriptions: Optional[str] = None,
    resources_directory: Optional[str] = None,
    resource_file: Optional[str] = None,
    resource_schema: Optional[str] = None,
) -> List[Optional[ClientRawResponse]]:
    if enable_validation:
        validate_resources(
            resource_type=resource_type,
            resources_directory=resources_directory,
            resource_file=resource_file,
            resource_schema=resource_schema,
        )
    resource_type_enum = _convert_resource_type_enum(resource_type)
    client = client_factory(
        cmd=cmd,
        resource_type=resource_type_enum,
        resource_group_name=resource_group_name,
        workspace_name=workspace_name,
        aux_subscriptions=aux_subscriptions,
    )
    resource_files = _get_resource_files(resource_file, resources_directory)

    return [
        _create_or_update_resource(
            client=client, resource_type=resource_type_enum, resource_file_path=resource_file
        )
        for resource_file in resource_files
    ]


def _get_existing_resource(
    client: BaseClient, resource_type: ResourceType, resource_params: ResourceParams
) -> Optional[Model]:
    """Fetches existing resource based on the given resource type. Returns None if resource does not exist"""
    if (
        resource_type is ResourceType.SCHEDULED_DETECTION
        or resource_type is ResourceType.MICROSOFT_SECURITY_DETECTION
    ):
        resource_params = cast(DetectionParams, resource_params)
        operation_type = OperationType.ALERT_RULE
        operation_id = resource_params.rule_id
    elif resource_type is ResourceType.DATA_SOURCE:
        resource_params = cast(ParserParams, resource_params)
        operation_type = OperationType.SAVED_SEARCH
        operation_id = resource_params.function_id
    else:
        raise ValueError("Requested resource type is not supported")
    try:
        logger.info("Check if resource already exists")
        return client.get_operation(
            operation_type=operation_type, operation_id=operation_id
        )
    except Exception:
        logger.info(
            "Resource %s does not exist in the target environment, creating a new instance ... ",
            resource_params.display_name,
        )
        return None


def _update_resource_etag(
    resource_type: ResourceType,
    resource_params: ResourceParams,
    existing_resource: Model,
) -> None:
    """Updates resource params etag with the existing resource etag based on the given resource type"""
    if (
        resource_type is ResourceType.SCHEDULED_DETECTION
        or resource_type is ResourceType.MICROSOFT_SECURITY_DETECTION
    ):
        existing_resource = cast(AlertRule, existing_resource)
        resource_params.etag = existing_resource.etag
    elif resource_type is ResourceType.DATA_SOURCE:
        existing_resource = cast(SavedSearch, existing_resource)
        resource_params.etag = existing_resource.additional_properties[ETAG_KEY]


def _link_playbook(
    multi_tenant_client: MultiTenantSecurityClient,
    rule_id: str,
    playbook_info: PlaybookInfo,
) -> ActionResponse:

    _unlink_playbooks(security_client=multi_tenant_client, rule_id=rule_id)
    action_request = multi_tenant_client.get_playbook_action_request(
        playbook_info=playbook_info
    )
    linked_playbook = multi_tenant_client.create_or_update_operation(
        operation_type=OperationType.ACTION,
        operation_id=playbook_info.name,
        operation=action_request,
        rule_id=rule_id,
    )

    logger.info(
        "Successfully linked Logic App %s to the detection", linked_playbook.name
    )
    return linked_playbook


def _unlink_playbooks(security_client: SecurityClient, rule_id: str):
    linked_playbooks: List[ActionResponse] = security_client.list_actions_by_alert_rule(
        rule_id=rule_id
    ).value
    for linked_playbook in linked_playbooks:
        security_client.delete_operation(
            operation_type=OperationType.ACTION,
            operation_id=linked_playbook.name,
            rule_id=rule_id,
        )


def _deploy_resource(
    client: BaseClient, resource_type: ResourceType, resource_params: ResourceParams
) -> ClientRawResponse:
    """Deploys the given resource"""
    if resource_type is ResourceType.SCHEDULED_DETECTION:
        resource_params = cast(ScheduledDetectionParams, resource_params)
        client = cast(MultiTenantSecurityClient, client)
        created_or_updated_detection = client.create_or_update_operation(
            operation_type=OperationType.ALERT_RULE,
            operation_id=resource_params.rule_id,
            operation=resource_params.alert_rule,
        )
        if resource_params.playbook_info:
            _link_playbook(
                multi_tenant_client=client,
                rule_id=resource_params.rule_id,
                playbook_info=resource_params.playbook_info,
            )
        else:
            _unlink_playbooks(security_client=client, rule_id=resource_params.rule_id)
        return created_or_updated_detection

    elif resource_type is ResourceType.MICROSOFT_SECURITY_DETECTION:
        resource_params = cast(MicrosoftSecurityDetectionParams, resource_params)
        operation_type = OperationType.ALERT_RULE
        operation_id = resource_params.rule_id
        operation = resource_params.alert_rule

    elif resource_type is ResourceType.DATA_SOURCE:
        client = cast(AnalyticsClient, client)
        resource_params = cast(ParserParams, resource_params)
        saved_search = client.generate_saved_search_from_parser_params(
            parser=resource_params
        )
        operation_type = OperationType.SAVED_SEARCH
        operation_id = resource_params.function_id
        operation = saved_search
    else:
        raise ValueError("Requested resource type is not supported")

    return client.create_or_update_operation(
        operation_type=operation_type, operation_id=operation_id, operation=operation
    )


def _create_or_update_resource(
    client: BaseClient, resource_type: ResourceType, resource_file_path: Path
) -> Optional[ClientRawResponse]:
    resource_params = resource_params_factory(
        resource_type=resource_type, resource_file_path=resource_file_path
    )
    if not resource_params:
        return None
    existing_resource = _get_existing_resource(
        client=client, resource_type=resource_type, resource_params=resource_params
    )
    if existing_resource:
        _update_resource_etag(
            resource_type=resource_type,
            resource_params=resource_params,
            existing_resource=existing_resource,
        )
    try:
        return _deploy_resource(
            client=client, resource_type=resource_type, resource_params=resource_params
        )
    except Exception as azCloudError:
        logger.error(
            "Failed to deploy resource %s due to %s",
            resource_params.display_name,
            str(azCloudError),
        )
        raise azCloudError


def generate_resource(
    resource_type: str,
    resources_directory: Optional[str] = None,
    skip_interactive: Optional[bool] = False,
    name: Optional[str] = None,
    create_directory: Optional[bool] = True,
    with_documentation: Optional[bool] = True,
) -> None:
    """Creates a scaffolding for the given resource based on the configured template"""
    resource_type_enum = _convert_resource_type_enum(resource_type)
    # Populate values for the resource
    if not skip_interactive:
        if not name:
            name = prompt(
                f"Name your {resource_type_enum.value}(alphanumeric without spaces): "
            )
            validate_name(name)
        if not create_directory:
            create_directory = prompt_y_n(
                f"Would you like to create a new directory for your {resource_type_enum.value}?"
            )
        if not with_documentation:
            with_documentation = prompt_y_n(
                f"Would you like to create a documentation file for your {resource_type_enum.value}?"
            )
    resources_directory: str = (
        resources_directory if resources_directory else os.getcwd()
    )
    resource_file_name: str = name + ".yaml"
    resource_template = _resolve_config_file(resource_type_enum, ResourceConfig.TEMPLATE)
    resource_config: str = resource_template.read_text().format(
        unique_id=str(uuid.uuid4()), name=name
    )

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
        resource_documentation = _resolve_config_file(
            resource_type_enum, ResourceConfig.DOCUMENTATION
        )
        _create_documentation(resource_documentation, name, directory_path)


def validate_resources(
    resource_type: str,
    resources_directory: Optional[str] = None,
    resource_file: Optional[str] = None,
    resource_schema: Optional[str] = None,
) -> None:
    """Validates the given resources against its configured JSON schema"""
    # TODO: check if there are resources with the same ID
    resource_type_enum = _convert_resource_type_enum(resource_type)
    resource_schema_file = _resolve_config_file(
        resource_type_enum, ResourceConfig.SCHEMA, resource_schema
    )
    schema = yaml.safe_load(resource_schema_file.read_text())
    resource_files = _get_resource_files(resource_file, resources_directory)
    for file in resource_files:
        logger.info(
            "Validating %s %s with schema at %s",
            resource_type_enum.value,
            file,
            resource_schema_file,
        )
        alert_rule = yaml.safe_load(file.read_text())
        try:
            jsonschema.validate(alert_rule, schema)
        except ValidationError as validationError:
            raise CLIError(validationError.message)
    logger.info("All validations successful!")


def _resolve_config_file(
    resource_type: ResourceType,
    resource_config: ResourceConfig,
    preferred_config: Optional[str] = None,
) -> Path:
    """
    Returns the most local config. If `preferred_config` is provided, it returns it.
    If not, looks for a local file. If that is not available, returns the config file bundled with the CLI
    """
    if preferred_config:
        config_file = Path(preferred_config)
    else:
        local_file = _get_local_config_file(resource_type, resource_config)
        fallback_file = RESOURCE_DEFAULTS[resource_type][resource_config][
            ResourceFetchMethod.FALLBACK
        ]
        config_file = local_file if local_file else fallback_file
    return config_file


def _get_local_config_file(
    resource_type: ResourceType, resource_config: ResourceConfig
) -> Optional[Path]:
    """Loads the local config file if available by traversing upto the HOME directory of the user"""
    file_name = RESOURCE_DEFAULTS[resource_type][resource_config][
        ResourceFetchMethod.LOCAL
    ]
    current_path = Path.cwd()
    while current_path not in [Path.home(), current_path.root]:
        local_file = current_path / file_name
        if local_file.exists():
            return local_file
        else:
            current_path = current_path.parent
            continue


def _get_resource_files(
    resource_file: Optional[str] = None, resources_directory: Optional[str] = None
) -> Union[Generator[Path, None, None], List[Path]]:
    """ Gets all the YAML files in the folder or just returns the original file if `resource_file` is provided """
    if resources_directory:
        resource_path = Path(resources_directory)
        resource_files = resource_path.glob("**/*.yaml")
    else:
        resource_files = [Path(resource_file)]
    return resource_files


def _create_documentation(
    documentation_template: Path, detection_name: str, documentation_location: Path
) -> None:
    documentation_template_content: str = documentation_template.read_text()
    documentation_content: str = (
        "# {} \n \n".format(detection_name) + documentation_template_content
    )
    documentation_file: Path = documentation_location / (detection_name + ".md")
    documentation_file.write_text(documentation_content)
