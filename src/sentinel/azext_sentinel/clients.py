import abc

from typing import Optional, Dict

from azure.cli.core.commands.client_factory import (
    get_mgmt_service_client,
    get_subscription_id,
)
from azext_sentinel.custom_models import ParserParams, PlaybookInfo

from .vendored_sdks.loganalytics.mgmt.loganalytics import LogAnalyticsManagementClient
from .vendored_sdks.loganalytics.mgmt.loganalytics.models import SavedSearch
from .vendored_sdks.logic_app.mgmt.logic.logic_management_client import (
    LogicManagementClient,
)
from .vendored_sdks.logic_app.mgmt.logic.models import WorkflowTriggerCallbackUrl
from .vendored_sdks.security_insights import SecurityInsights
from .vendored_sdks.security_insights.models import ActionRequest

from .constants import (
    DEFAULT_TRIGGER_NAME,
    OperationType,
    ResourceType,
)

DEFAULT_RESOURCE_PROVIDER = "Microsoft.OperationalInsights"
SAVED_SEARCH_ID_TEMPLATE = (
    "subscriptions/{}/resourceGroups/{}/providers/"
    "Microsoft.OperationalInsights/workspaces/{}/savedSearches/{}"
)
PARSER_CATEGORY_NAME = "parser"
RULE_ID_IDENTIFIER = "rule_id"


class BaseClient(abc.ABC):
    """
    Base client for deploying different Azure Sentinel resources. Based on the resource type
    the subclass client is defined and calls relevant endpoints
    """

    def __init__(
        self,
        resource_group_name: str,
        workspace_name: str,
        resource_provider: Optional[str] = None,
    ):
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name
        self.resource_provider = resource_provider or DEFAULT_RESOURCE_PROVIDER

    @classmethod
    @abc.abstractmethod
    def from_cmd(cls, cmd, resource_group_name: str, workspace_name: str, **kwargs):
        ...

    @abc.abstractmethod
    def create_or_update_operation(
        self, operation_type: OperationType, operation_id: str, operation, **kwargs
    ):
        ...

    @abc.abstractmethod
    def get_operation(
        self,
        operation_type: OperationType,
        operation_id: str,
        **kwargs,
    ):
        ...

    @abc.abstractmethod
    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        ...


class AnalyticsClient(BaseClient):
    """Client for deploying resources that require log-analytic endpoints.
    It contains `LogAnalyticsManagementClient` for calling relevant endpoints.
    """

    def __init__(
        self,
        log_analytics_client: LogAnalyticsManagementClient,
        subscription_id: str,
        **kwargs,
    ):
        self.client = log_analytics_client
        self.subscription_id = subscription_id
        super().__init__(**kwargs)

    @classmethod
    def from_cmd(cls, cmd, resource_group_name: str, workspace_name: str, **kwargs):
        log_analytics_client = get_mgmt_service_client(
            cmd.cli_ctx, LogAnalyticsManagementClient
        )
        subscription_id = get_subscription_id(cmd.cli_ctx)
        return cls(
            log_analytics_client=log_analytics_client,
            subscription_id=subscription_id,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )

    @property
    def saved_searches(self):
        return self.client.saved_searches

    def get_operation(
        self,
        operation_type: OperationType,
        operation_id: str,
        **kwargs,
    ):
        if operation_type is OperationType.SAVED_SEARCH:
            operation = self.saved_searches.get(
                resource_group_name=self.resource_group_name,
                workspace_name=self.workspace_name,
                saved_search_id=operation_id,
                **kwargs,
            )
        else:
            raise NotImplementedError

        return operation

    def generate_saved_search_from_parser_params(
        self, parser: ParserParams, id_template: Optional[str] = None
    ) -> SavedSearch:
        id_template = id_template or SAVED_SEARCH_ID_TEMPLATE
        return SavedSearch(
            id=id_template.format(
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                parser.function_id,
            ),
            display_name=parser.display_name,
            function_alias=parser.display_name,
            query=parser.query,
            e_tag=parser.etag,
            category=PARSER_CATEGORY_NAME,
        )

    def create_or_update_operation(
        self, operation_type: OperationType, operation_id: str, operation, **kwargs
    ):
        if operation_type is OperationType.SAVED_SEARCH:
            return self.saved_searches.create_or_update(
                resource_group_name=self.resource_group_name,
                workspace_name=self.workspace_name,
                saved_search_id=operation_id,
                parameters=operation,
                **kwargs,
            )
        raise NotImplementedError("Operation type is not supported")

    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        raise NotImplementedError


class MultiClients:
    """Encapsulates an instance of `SecurityInsight` and an instance of `LogicManagementClient`"""

    def __init__(
        self,
        security_insight_client: SecurityInsights,
        logic_management_client: LogicManagementClient,
    ):
        self.security_insight_client = security_insight_client
        self.logic_management_client = logic_management_client

    @classmethod
    def from_cmd(cls, cmd):
        logic_management_client: LogicManagementClient = get_mgmt_service_client(
            cli_ctx=cmd.cli_ctx, client_or_resource_type=LogicManagementClient
        )
        security_insights_client: SecurityInsights = get_mgmt_service_client(
            cli_ctx=cmd.cli_ctx, client_or_resource_type=SecurityInsights
        )
        return cls(
            security_insight_client=security_insights_client,
            logic_management_client=logic_management_client,
        )


class SecurityClient(BaseClient):
    """Client for resources like detections that needs both `SecurityInsights` and `LogicManagementClient`"""

    def __init__(
        self,
        multi_clients: MultiClients,
        **kwargs,
    ):
        self.multi_clients = multi_clients
        self.security_insight_client = multi_clients.security_insight_client
        self.logic_management_client = multi_clients.logic_management_client
        super().__init__(**kwargs)

    @classmethod
    def from_cmd(cls, cmd, resource_group_name: str, workspace_name: str, **kwargs):
        multi_clients = MultiClients.from_cmd(cmd)
        return cls(
            multi_clients=multi_clients,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )

    @property
    def subscription_id(self):
        return self.security_insight_client.config.subscription_id

    @property
    def alert_rules(self):
        return self.security_insight_client.alert_rules

    @property
    def actions(self):
        return self.security_insight_client.actions

    @property
    def workflows(self):
        return self.logic_management_client.workflows

    @property
    def workflow_version_triggers(self):
        return self.logic_management_client.workflow_version_triggers

    def get_operation(self, operation_type: OperationType, operation_id: str, **kwargs):
        if operation_type is OperationType.ALERT_RULE:
            return self.alert_rules.get(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                rule_id=operation_id,
                **kwargs,
            )
        elif operation_type is OperationType.WORKFLOW:
            return self.workflows.get(
                resource_group_name=self.resource_group_name,
                workflow_name=operation_id,
                **kwargs,
            )
        raise NotImplementedError("Operation type is not supported")

    def create_or_update_operation(
        self, operation_type: OperationType, operation_id: str, operation, **kwargs
    ):
        if operation_type is OperationType.ALERT_RULE:
            return self.alert_rules.create_or_update(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                rule_id=operation_id,
                alert_rule=operation,
                **kwargs,
            )
        elif operation_type is OperationType.ACTION:
            return self.alert_rules.create_or_update_action(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                action_id=operation_id,
                action=operation,
                **kwargs,
            )
        raise NotImplementedError("Operation type is not supported")

    def list_actions_by_alert_rule(self, rule_id: str, **kwargs):
        return self.actions.list_by_alert_rule(
            resource_group_name=self.resource_group_name,
            operational_insights_resource_provider=self.resource_provider,
            workspace_name=self.workspace_name,
            rule_id=rule_id,
            **kwargs,
        )

    def get_workflow_callback_url(
        self,
        workflow_name: str,
        version_id: str,
        trigger_name: Optional[str] = None,
        **kwargs,
    ) -> WorkflowTriggerCallbackUrl:
        return self.workflow_version_triggers.list_callback_url(
            resource_group_name=self.resource_group_name,
            workflow_name=workflow_name,
            version_id=version_id,
            trigger_name=trigger_name or DEFAULT_TRIGGER_NAME,
            **kwargs,
        )

    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        if operation_type is OperationType.ACTION:
            return self.alert_rules.delete_action(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                action_id=operation_id,
                **kwargs,
            )
        raise NotImplementedError("Operation type is not supported")


class MultiTenantSecurityClient(SecurityClient):
    """Multi-tenant client for getting/creating/updating resources across tenants"""

    def __init__(self, aux_clients: Dict[str, MultiClients], **kwargs):
        self.aux_clients = aux_clients
        super().__init__(**kwargs)

    @classmethod
    def from_cmd(
        cls, cmd, resource_group_name: str, workspace_name: str, **kwargs
    ) -> BaseClient:
        aux_subscriptions = kwargs.get("aux_subscriptions")
        aux_subscriptions = aux_subscriptions.split(",") if aux_subscriptions else []
        aux_clients = {
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
        multi_clients = MultiClients.from_cmd(cmd)

        return cls(
            aux_clients=aux_clients,
            multi_clients=multi_clients,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )

    def get_target_client(
        self, subscription_id: str, resource_group_name: str, workspace_name: str
    ) -> SecurityClient:
        """Returns a `SecurityClient` for the given target environment from `self.aux_clients` dict.
        Returns self object if the given tenant is the same as object's.
        """
        if subscription_id == self.subscription_id:
            return self  # ne need to use aux clients
        elif subscription_id in self.aux_clients:
            return SecurityClient(
                multi_clients=self.aux_clients[subscription_id],
                resource_group_name=resource_group_name,
                workspace_name=workspace_name,
            )
        raise ValueError(
            f"Client for Subscription id: {subscription_id} is not initialized. "
            f"Please add subscription using --aux-subscriptions flag"
        )

    def get_playbook_action_request(self, playbook_info: PlaybookInfo) -> ActionRequest:
        """Returns the given playbook action request containing its trigger uri and its Logic App's resource id"""
        target_client = self.get_target_client(
            subscription_id=playbook_info.subscription_id,
            resource_group_name=playbook_info.resource_group_name,
            workspace_name=playbook_info.workspace_name,
        )
        playbook = target_client.get_operation(
            operation_type=OperationType.WORKFLOW, operation_id=playbook_info.name
        )
        workflow_callback_url = target_client.get_workflow_callback_url(
            workflow_name=playbook.name, version_id=playbook.version
        )
        trigger_uri = workflow_callback_url.value
        return ActionRequest(logic_app_resource_id=playbook.id, trigger_uri=trigger_uri)


def client_factory(
    cmd,
    resource_type: ResourceType,
    resource_group_name: str,
    workspace_name: str,
    aux_subscriptions: Optional[str] = None,
) -> BaseClient:
    """Factory method for instantiating a resource client based on the given resource type"""
    if resource_type is ResourceType.SCHEDULED_DETECTION:
        return MultiTenantSecurityClient.from_cmd(
            cmd=cmd,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
            aux_subscriptions=aux_subscriptions,
        )
    elif resource_type is ResourceType.DATA_SOURCE:
        return AnalyticsClient.from_cmd(
            cmd=cmd,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )
    elif resource_type is ResourceType.MICROSOFT_SECURITY_DETECTION:
        return SecurityClient.from_cmd(
            cmd=cmd,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )
    raise NotImplementedError("Requested resource type is not supported")
