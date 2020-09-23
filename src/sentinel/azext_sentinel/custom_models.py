from typing import Optional

from azext_sentinel.vendored_sdks.security_insights.models import ScheduledAlertRule

PLAYBOOK_KEY = "playbook"
ADDITIONAL_METADATA_KEY = "additional_metadata"
ID_KEY = "id"
FUNCTION_ID_KEY = "function_id"
DISPLAY_NAME_KEY = "display_name"
QUERY_KEY = "query"
ETAG_KEY = "etag"


class PlaybookInfo:
    """PlaybookInfo encapsulates playbook information and supports linking playbooks that are deployed in
    other tenants. If resource_group_name and workspace_name are not given, the given playbook must exist
    in the target resource group and workspace.
    """
    def __init__(
            self,
            name: str,
            subscription_id: str,
            resource_group_name: str,
            workspace_name: str
    ):
        self.name = name
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name


class ParserParams:
    def __init__(self, **kwargs):
        self.function_id = kwargs.get(FUNCTION_ID_KEY, None)
        self.display_name = kwargs.get(DISPLAY_NAME_KEY, None)
        self.query = kwargs.get(QUERY_KEY, None)
        self.etag = kwargs.get(ETAG_KEY, None)


class AlertParams:
    def __init__(self, **kwargs):
        playbook = kwargs.pop(PLAYBOOK_KEY, None)
        self.playbook_info = PlaybookInfo(**playbook) if playbook else None
        self.additional_metadata = kwargs.pop(ADDITIONAL_METADATA_KEY, None)
        self.rule_id = kwargs[ID_KEY]
        self.alert_rule = ScheduledAlertRule(**kwargs)

    @property
    def etag(self) -> Optional[str]:
        return self.alert_rule.etag

    @etag.setter
    def etag(self, etag_value: str) -> None:
        self.alert_rule.etag = etag_value
