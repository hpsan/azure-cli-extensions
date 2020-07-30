# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import uuid
import jsonschema
import yaml


from pathlib import Path
from typing import List, Union, Generator, Optional

from azext_sentinel.custom_models import ParserParams, AlertParams, PlaybookInfo
from azure.cli.core.commands.client_factory import (
    get_mgmt_service_client,
    get_subscription_id,
)
from jsonschema import ValidationError
from knack.log import get_logger
from knack.prompting import prompt, prompt_y_n
from knack.util import CLIError

from .vendored_sdks.loganalytics.mgmt.loganalytics import LogAnalyticsManagementClient
from .vendored_sdks.loganalytics.mgmt.loganalytics.models import SavedSearch
from ._validators import validate_name
from .clients import (
    SecurityClient,
    AnalyticsClient,
    MultiClients,
    MultiTenantSecurityClient,
)
from .constants import (
    ETAG_KEY,
    OperationType,
    ResourceType,
    RESOURCE_DEFAULTS,
    ResourceConfig,
    ResourceFetchMethod,
)
from .vendored_sdks.logic_app.mgmt.logic.logic_management_client import (
    LogicManagementClient,
)
from .vendored_sdks.security_insights import SecurityInsights
from .vendored_sdks.security_insights.models import (
    AlertRule,
    ActionResponse,
    ActionRequest,
)

logger = get_logger(__name__)

PLAYBOOK_NAME_KEY = "playbook_name"
ADDITIONAL_METADATA_KEY = "additional_metadata"
ID_KEY = "id"
FUNCTION_ID_KEY = "function_id"
DISPLAY_NAME_KEY = "display_name"
QUERY_KEY = "query"
ETAG_KEY = "etag"

def create_detections(
    cmd,
    resource_group_name: str,
    workspace_name: str,
    aux_subscriptions: Optional[str] = None,
    detections_directory: Optional[str] = None,
    detection_file: Optional[str] = None,
    detection_schema: Optional[str] = None,
    enable_validation: Optional[bool] = False,
    force_link_playbook: Optional[bool] = False,
) -> List[AlertRule]:
    """Loads the detection config from the local file/dir, validates it and deploys it"""
    aux_subscriptions = aux_subscriptions.split(",") if aux_subscriptions else None
    logic_management_client: LogicManagementClient = get_mgmt_service_client(
        cli_ctx=cmd.cli_ctx, client_or_resource_type=LogicManagementClient
    )
    security_insights_client: SecurityInsights = get_mgmt_service_client(
        cli_ctx=cmd.cli_ctx, client_or_resource_type=SecurityInsights
    )
    multi_clients = MultiClients(
        security_insight_client=security_insights_client,
        logic_management_client=logic_management_client,
    )
    security_client = SecurityClient(
        multi_clients=multi_clients,
        resource_group_name=resource_group_name,
        workspace_name=workspace_name,
    )
    aux_clients = (
        {
            subscription_id: MultiClients(
                security_insight_client=get_mgmt_service_client(
                    cli_ctx=cmd.cli_ctx,
                    client_or_resource_type=SecurityInsights,
                    subscription_id=subscription_id,
                ),
                logic_management_client=get_mgmt_service_client(
                    cli_ctx=cmd.cli_ctx,
                    client_or_resource_type=LogicManagementClient,
                    subscription_id=subscription_id,
                ),
            )
            for subscription_id in aux_subscriptions
        }
        if aux_subscriptions
        else {}
    )
    multi_tenant_client = MultiTenantSecurityClient(
        primary_client=security_client, aux_clients=aux_clients
    )
    if enable_validation:
        validate_detections(detections_directory, detection_file, detection_schema)
    detection_files = _get_resource_files(detection_file, detections_directory)

    return [
        _create_or_update_detection(
            multi_tenant_client=multi_tenant_client,
            detection_file=detection_file,
            force_link_playbook=force_link_playbook,
        )
        for detection_file in detection_files
    ]


def validate_detections(
    detections_directory: Optional[str] = None,
    detection_file: Optional[str] = None,
    detection_schema: Optional[str] = None,
) -> None:
    """Validates the detections against its configured JSON schema"""
    validate_resources(
        resource_type=ResourceType.DETECTION,
        resources_directory=detections_directory,
        resource_file=detection_file,
        resource_schema=detection_schema,
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
        with_documentation=with_documentation,
    )


def create_data_sources(
    cmd,
    resource_group_name: str,
    workspace_name: str,
    data_sources_directory: Optional[str] = None,
    data_source_file: Optional[str] = None,
    data_source_schema: Optional[str] = None,
    enable_validation: Optional[bool] = False,
) -> List[SavedSearch]:
    """
    Loads the data source config from the local file/dir, validates it and deploys it
    Note that at this point, it only deploys
    the parser associated with the data source and not other related entities such as data source connectors
    """
    client: LogAnalyticsManagementClient = get_mgmt_service_client(
        cmd.cli_ctx, LogAnalyticsManagementClient
    )
    subscription_id = get_subscription_id(cmd.cli_ctx)
    analytics_client = AnalyticsClient(
        log_analytics_client=client,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
        workspace_name=workspace_name,
    )

    if enable_validation:
        validate_data_sources(
            data_sources_directory, data_source_file, data_source_schema
        )

    data_source_files = _get_resource_files(data_source_file, data_sources_directory)
    return [
        _create_or_update_data_source(
            analytics_client=analytics_client, data_source_file=data_source_file
        )
        for data_source_file in data_source_files
    ]


def generate_data_source(
    data_sources_directory: Optional[str] = None,
    skip_interactive: Optional[bool] = False,
    name: Optional[str] = None,
    create_directory: Optional[bool] = True,
    with_documentation: Optional[bool] = True,
):
    """Creates a scaffolding for the data source based on the configured template"""
    generate_resource(
        resource_type=ResourceType.DATA_SOURCE,
        resources_directory=data_sources_directory,
        skip_interactive=skip_interactive,
        name=name,
        create_directory=create_directory,
        with_documentation=with_documentation,
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
            name = prompt(
                f"Name your {resource_type.value}(alphanumeric without spaces): "
            )
            validate_name(name)
        if not create_directory:
            create_directory = prompt_y_n(
                f"Would you like to create a new directory for your {resource_type.value}?"
            )
        if not with_documentation:
            with_documentation = prompt_y_n(
                f"Would you like to create a documentation file for your {resource_type.value}?"
            )
    resources_directory: str = (
        resources_directory if resources_directory else os.getcwd()
    )
    resource_file_name: str = name + ".yaml"
    resource_template = _resolve_config_file(resource_type, ResourceConfig.TEMPLATE)
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
            resource_type, ResourceConfig.DOCUMENTATION
        )
        _create_documentation(resource_documentation, name, directory_path)


def validate_data_sources(
    data_sources_directory: Optional[str] = None,
    data_source_file: Optional[str] = None,
    data_source_schema: Optional[str] = None,
):
    """Validates the data source against its configured JSON schema"""
    validate_resources(
        resource_type=ResourceType.DATA_SOURCE,
        resources_directory=data_sources_directory,
        resource_file=data_source_file,
        resource_schema=data_source_schema,
    )


def validate_resources(
    resource_type: ResourceType,
    resources_directory: Optional[str] = None,
    resource_file: Optional[str] = None,
    resource_schema: Optional[str] = None,
) -> None:
    """Validates the given resources against its configured JSON schema"""
    # TODO: check if there are resources with the same ID

    resource_schema_file = _resolve_config_file(
        resource_type, ResourceConfig.SCHEMA, resource_schema
    )
    schema = yaml.safe_load(resource_schema_file.read_text())
    resource_files = _get_resource_files(resource_file, resources_directory)
    for file in resource_files:
        logger.info(
            "Validating %s %s with schema at %s",
            resource_type.value,
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


def _create_or_update_detection(
    multi_tenant_client: MultiTenantSecurityClient,
    detection_file: Path,
    force_link_playbook: bool,
) -> AlertRule:
    """Loads the detection config from the local file/dir and deploys it"""
    security_client = multi_tenant_client.primary_client
    alert_dict = yaml.safe_load(detection_file.read_text())
    alert_params = AlertParams(**alert_dict)
    playbook_info = alert_params.playbook_info
    # Fetch the existing rule to update if it already exists
    try:
        existing_rule = security_client.get_operation(
            operation_type=OperationType.ALERT_RULE, operation_id=alert_params.rule_id
        )
        alert_params.etag = existing_rule.etag
    except Exception:
        pass
    # Create the rule
    try:
        created_alert: AlertRule = security_client.create_or_update_operation(
            operation_type=OperationType.ALERT_RULE,
            operation_id=alert_params.rule_id,
            operation=alert_params.alert_rule,
        )
    except Exception as azCloudError:
        logger.error(
            "Unable to create/update the detection %s due to %s",
            detection_file,
            str(azCloudError),
        )
        raise azCloudError

    # Link the playbook if it is configured
    # Caveat: When playbooks get deployed, their callback url get changed. Thus, it is necessary to have
    # force_link_playbook flag set for CI/CD pipeline deployments
    if playbook_info and force_link_playbook:
        _link_playbook(
            multi_tenant_client=multi_tenant_client,
            rule_id=alert_params.rule_id,
            playbook_info=playbook_info,
        )
    elif not playbook_info:
        _unlink_all_playbooks(
            security_client=security_client, rule_id=alert_params.rule_id
        )

    return created_alert


def _get_playbook_action_request(
    multi_tenant_client: MultiTenantSecurityClient, playbook_info: PlaybookInfo
) -> str:
    security_client = multi_tenant_client.get_security_client(
        subscription_id=playbook_info.subscription_id,
        resource_group_name=playbook_info.resource_group_name,
        workspace_name=playbook_info.workspace_name,
    )
    playbook = security_client.get_operation(
        operation_type=OperationType.WORKFLOW,
        operation_id=playbook_info.name,
    )
    workflow_callback_url = security_client.get_workflow_callback_url(
        workflow_name=playbook.name,
        version_id=playbook.version,
    )
    trigger_uri = workflow_callback_url.value

    return ActionRequest(logic_app_resource_id=playbook.id, trigger_uri=trigger_uri)


def _link_playbook(
    multi_tenant_client: MultiTenantSecurityClient,
    rule_id: str,
    playbook_info: PlaybookInfo,
) -> ActionResponse:

    security_client = multi_tenant_client.primary_client
    _unlink_all_playbooks(security_client=security_client, rule_id=rule_id)
    action_request = _get_playbook_action_request(
        multi_tenant_client=multi_tenant_client, playbook_info=playbook_info
    )
    linked_playbook = security_client.create_or_update_operation(
        operation_type=OperationType.ACTION,
        operation_id=playbook_info.name,
        operation=action_request,
        rule_id=rule_id,
    )

    return linked_playbook


def _unlink_all_playbooks(security_client: SecurityClient, rule_id: str):
    linked_playbooks: List[ActionResponse] = security_client.list_actions_by_alert_rule(
        rule_id=rule_id
    ).value
    for linked_playbook in linked_playbooks:
        security_client.delete_operation(
            operation_type=OperationType.ACTION,
            operation_id=linked_playbook.name,
            rule_id=rule_id,
        )


def _create_or_update_data_source(
    analytics_client: AnalyticsClient, data_source_file: Path
) -> Optional[SavedSearch]:
    """
    Loads the data soure config from the local file/dir and deploys it. Note that at this point, it only deploys
    the parser associated with the data source and not other related entities such as data source connectors
    """
    data_source = yaml.safe_load(data_source_file.read_text())
    parser = data_source.get("parser")
    if not parser:
        return

    parser_params = ParserParams(**parser)
    # Fetch the existing parser to update if it already exists
    try:
        existing_parser: SavedSearch = analytics_client.get_operation(
            operation_type=OperationType.SAVED_SEARCH,
            operation_id=parser_params.function_id,
        )
        parser_params.etag = existing_parser.additional_properties[ETAG_KEY]
    except Exception:
        pass
    try:
        saved_search = analytics_client.generate_saved_search_from_parser_params(
            parser=parser_params
        )
        created_saved_search: SavedSearch = analytics_client.create_or_update_operation(
            operation_type=OperationType.SAVED_SEARCH,
            operation_id=parser_params.function_id,
            operation=saved_search,
        )
    except Exception as azCloudError:
        logger.error(
            "Unable to create/update the parser %s due to %s",
            data_source_file,
            str(azCloudError),
        )
        raise azCloudError

    return created_saved_search


def _create_documentation(
    documentation_template: Path, detection_name: str, documentation_location: Path
) -> None:
    documentation_template_content: str = documentation_template.read_text()
    documentation_content: str = (
        "# {} \n \n".format(detection_name) + documentation_template_content
    )
    documentation_file: Path = documentation_location / (detection_name + ".md")
    documentation_file.write_text(documentation_content)
