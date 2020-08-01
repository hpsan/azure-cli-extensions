from typing import Optional

from azext_sentinel.vendored_sdks.security_insights.models import ScheduledAlertRule

PLAYBOOK_NAME_KEY = "playbook_name"
ADDITIONAL_METADATA_KEY = "additional_metadata"
ID_KEY = "id"
FUNCTION_ID_KEY = "function_id"
DISPLAY_NAME_KEY = "display_name"
QUERY_KEY = "query"
ETAG_KEY = "etag"


class ParserParams:
    def __init__(self, **kwargs):
        self.function_id = kwargs.get(FUNCTION_ID_KEY, None)
        self.display_name = kwargs.get(DISPLAY_NAME_KEY, None)
        self.query = kwargs.get(QUERY_KEY, None)
        self.etag = kwargs.get(ETAG_KEY, None)


class AlertParams:
    def __init__(self, **kwargs):
        self.playbook_name = kwargs.pop(PLAYBOOK_NAME_KEY, None)
        self.additional_metadata = kwargs.pop(ADDITIONAL_METADATA_KEY, None)
        self.rule_id = kwargs[ID_KEY]
        self.alert_rule = ScheduledAlertRule(**kwargs)

    @property
    def etag(self) -> Optional[str]:
        return self.alert_rule.etag

    @etag.setter
    def etag(self, etag_value: str) -> None:
        self.alert_rule.etag = etag_value
