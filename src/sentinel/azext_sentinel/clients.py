import abc

from typing import Optional

from azext_sentinel.custom_models import ParserParams

from .vendored_sdks.loganalytics.mgmt.loganalytics import LogAnalyticsManagementClient
from .vendored_sdks.loganalytics.mgmt.loganalytics.models import SavedSearch
from .vendored_sdks.logic_app.mgmt.logic.logic_management_client import (
    LogicManagementClient,
)
from .vendored_sdks.logic_app.mgmt.logic.models import WorkflowTriggerCallbackUrl
from .vendored_sdks.security_insights import SecurityInsights

from azext_sentinel.constants import (
    DEFAULT_TRIGGER_NAME,
    OperationType,
)

DEFAULT_RESOURCE_PROVIDER = "Microsoft.OperationalInsights"
SAVED_SEARCH_ID_TEMPLATE = (
    "subscriptions/{}/resourceGroups/{}/providers/"
    "Microsoft.OperationalInsights/workspaces/{}/savedSearches/{}"
)
PARSER_CATEGORY_NAME = "parser"
RULE_ID_IDENTIFIER = "rule_id"


class BaseClient(abc.ABC):
    def __init__(
        self,
        resource_group_name: str,
        workspace_name: str,
        resource_provider: Optional[str] = None,
    ):
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name
        self.resource_provider = resource_provider or DEFAULT_RESOURCE_PROVIDER

    @abc.abstractmethod
    def create_or_update_operation(
        self, operation_type: OperationType, operation_id: str, operation, **kwargs
    ):
        ...

    @abc.abstractmethod
    def get_operation(self, operation_type: OperationType, operation_id: str, **kwargs):
        ...

    @abc.abstractmethod
    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        ...


class AnalyticsClient(BaseClient):
    def __init__(
        self,
        log_analytics_client: LogAnalyticsManagementClient,
        subscription_id: str,
        **kwargs,
    ):
        self.client = log_analytics_client
        self.subscription_id = subscription_id
        super().__init__(**kwargs)

    @property
    def saved_searches(self):
        return self.client.saved_searches

    def get_operation(self, operation_type: OperationType, operation_id: str, **kwargs):
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
            created_or_updated = self.saved_searches.create_or_update(
                resource_group_name=self.resource_group_name,
                workspace_name=self.workspace_name,
                saved_search_id=operation_id,
                parameters=operation,
                **kwargs,
            )
        else:
            raise NotImplementedError
        return created_or_updated

    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        raise NotImplementedError


class SecurityClient(BaseClient):
    def __init__(
        self,
        security_insight_client: SecurityInsights,
        logic_management_client: LogicManagementClient,
        **kwargs,
    ):
        self.security_insight_client = security_insight_client
        self.logic_management_client = logic_management_client
        super().__init__(**kwargs)

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
            operation = self.alert_rules.get(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                rule_id=operation_id,
                **kwargs,
            )
        elif operation_type is OperationType.WORKFLOW:
            operation = self.workflows.get(
                resource_group_name=self.resource_group_name,
                workflow_name=operation_id,
                **kwargs,
            )
        else:
            raise NotImplementedError
        return operation

    def create_or_update_operation(
        self, operation_type: OperationType, operation_id: str, operation, **kwargs
    ):
        if operation_type is OperationType.ALERT_RULE:
            created_or_updated = self.alert_rules.create_or_update(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                rule_id=operation_id,
                alert_rule=operation,
                **kwargs,
            )
        elif operation_type is OperationType.ACTION:
            created_or_updated = self.alert_rules.create_or_update_action(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                action_id=operation_id,
                action=operation,
                **kwargs,
            )
        else:
            raise NotImplementedError
        return created_or_updated

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

    def is_action_updated(self, rule_id: str, action_name: str, **kwargs) -> bool:
        existing_actions = self.list_actions_by_alert_rule(rule_id=rule_id, **kwargs).value
        # New deployment of a resource (such as playbooks) changes its callback uri
        if existing_actions:
            existing_action = existing_actions[0]
            existing_callback_uri = self.get_workflow_callback_url(
                workflow_name=existing_action.name,
                version_id=existing_action.version).value
            new_action = self.get_operation(
                operation_type=OperationType.WORKFLOW, operation_id=action_name
            )
            new_callback_uri = self.get_workflow_callback_url(
                workflow_name=new_action.name, version_id=new_action.version
            ).value

            if existing_callback_uri == new_callback_uri:
                return False

        return True

    def delete_operation(
        self, operation_type: OperationType, operation_id: str, **kwargs
    ):
        if operation_type is OperationType.ACTION:
            deleted_operation = self.alert_rules.delete_action(
                resource_group_name=self.resource_group_name,
                operational_insights_resource_provider=self.resource_provider,
                workspace_name=self.workspace_name,
                action_id=operation_id,
                **kwargs,
            )
        else:
            raise NotImplementedError
        return deleted_operation
