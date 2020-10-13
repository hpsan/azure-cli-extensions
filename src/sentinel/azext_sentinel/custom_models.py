import abc
import yaml
from pathlib import Path

from typing import Optional

from azext_sentinel.vendored_sdks.security_insights.models import (
    ScheduledAlertRule,
    MicrosoftSecurityIncidentCreationAlertRule,
    AlertRule,
)

from .constants import ResourceType

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
        workspace_name: str,
    ):
        self.name = name
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name


class ResourceParams(abc.ABC):
    """Base object for encapsulating Azure Sentinel resources"""

    @property   # type: ignore
    @abc.abstractmethod
    def etag(self) -> str:
        ...

    @etag.setter    # type: ignore
    @abc.abstractmethod
    def etag(self, etag_value: str) -> None:
        ...

    @property   # type: ignore
    @abc.abstractmethod
    def display_name(self) -> str:
        ...

    @display_name.setter    # type: ignore
    @abc.abstractmethod
    def display_name(self, display_name: str) -> None:
        ...


class ParserParams(ResourceParams):
    """Encapsulates datasource configuration parameters"""

    def __init__(self, **kwargs):
        self.function_id = kwargs.get(FUNCTION_ID_KEY, None)
        self.query = kwargs.get(QUERY_KEY, None)
        self._etag = kwargs.get(ETAG_KEY, None)
        self._display_name = kwargs.get(DISPLAY_NAME_KEY, None)

    @property
    def etag(self) -> str:
        return self._etag

    @etag.setter
    def etag(self, etag_value) -> None:
        self._etag = etag_value

    @property
    def display_name(self) -> str:
        return self._display_name

    @display_name.setter
    def display_name(self, display_name: str) -> None:
        self._display_name = display_name


class DetectionParams(ResourceParams):
    """Encapsulates detection configuration parameters"""

    alert_rule: AlertRule

    def __init__(self, **kwargs):
        self.rule_id = kwargs[ID_KEY]

    @property
    def display_name(self) -> str:
        return self.alert_rule.display_name

    @display_name.setter
    def display_name(self, display_name: str) -> None:
        self.alert_rule.display_name = display_name

    @property
    def etag(self) -> str:
        return self.alert_rule.etag

    @etag.setter
    def etag(self, etag_value) -> None:
        self.alert_rule.etag = etag_value


class ScheduledDetectionParams(DetectionParams):
    """Encapsulate scheduled detection configuration parameters"""

    def __init__(self, **kwargs):
        playbook = kwargs.pop(PLAYBOOK_KEY, None)
        self.playbook_info = PlaybookInfo(**playbook) if playbook else None
        self.additional_metadata = kwargs.pop(ADDITIONAL_METADATA_KEY, None)
        super().__init__(**kwargs)
        self.alert_rule = ScheduledAlertRule(**kwargs)


class MicrosoftSecurityDetectionParams(DetectionParams):
    """Encapsulates Microsoft Security incident creation detection configuration parameters"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.alert_rule = MicrosoftSecurityIncidentCreationAlertRule(**kwargs)


def resource_params_factory(
    resource_type: ResourceType, resource_file_path: Path
) -> Optional[ResourceParams]:
    """Factory method for instantiating resource params based on the given resource type"""
    resource_dict = yaml.safe_load(resource_file_path.read_text())
    if resource_type is ResourceType.SCHEDULED_DETECTION:
        return ScheduledDetectionParams(**resource_dict)
    elif resource_type is ResourceType.DATA_SOURCE:
        parser = resource_dict.get("parser")
        return ParserParams(**parser) if parser else None
    elif resource_type is ResourceType.MICROSOFT_SECURITY_DETECTION:
        return MicrosoftSecurityDetectionParams(**resource_dict)

    raise NotImplementedError("Requested resource type is not supported")
