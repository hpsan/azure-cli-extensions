from enum import Enum
from pathlib import Path

DEFAULTS_DIR: Path = Path(__file__).parent

DEFAULT_DETECTION_SCHEMA: Path = DEFAULTS_DIR / "default_detection_schema.yaml"
DEFAULT_DETECTION_DOCUMENTATION: Path = (
    DEFAULTS_DIR / "default_detection_documentation.md"
)
DEFAULT_DETECTION_TEMPLATE: Path = DEFAULTS_DIR / "default_detection_template.yaml"
LOCAL_DETECTION_TEMPLATE: str = ".detection_template.yaml"
LOCAL_DETECTION_SCHEMA: str = ".detection_schema.json"
LOCAL_DETECTION_DOCUMENTATION: str = ".detection_documentation.md"

DEFAULT_MICROSOFT_SECURITY_DETECTION_SCHEMA: Path = (
    DEFAULTS_DIR / "default_msft_security_detection_schema.yaml"
)
DEFAULT_MICROSOFT_SECURITY_DETECTION_TEMPLATE: Path = (
    DEFAULTS_DIR / "default_msft_security_detection_template.yaml"
)
DEFAULT_MICROSOFT_SECURITY_DETECTION_DOCUMENTATION: Path = (
    DEFAULTS_DIR / "default_msft_security_documentation.md"
)
LOCAL_MICROSOFT_SECURITY_DETECTION_TEMPLATE: str = ".msft_detection_template.yaml"
LOCAL_MICROSOFT_SECURITY_DETECTION_SCHEMA: str = ".msft_security_detection_schema.json"
LOCAL_MICROSOFT_SECURITY_DETECTION_DOCUMENTATION: str = (
    ".msft_security_detection_documentation.md"
)

DEFAULT_DATA_SOURCE_SCHEMA: Path = DEFAULTS_DIR / "default_data_source_schema.yaml"
DEFAULT_DATA_SOURCE_TEMPLATE: Path = DEFAULTS_DIR / "default_data_source_template.yaml"
DEFAULT_DATA_SOURCE_DOCUMENTATION: Path = (
    DEFAULTS_DIR / "default_data_source_documentation.md"
)
LOCAL_DATA_SOURCE_TEMPLATE: str = ".data_source_template.yaml"
LOCAL_DATA_SOURCE_SCHEMA: str = ".data_source_schema.json"
LOCAL_DATA_SOURCE_DOCUMENTATION: str = ".data_source_documentation.md"

FUNCTION_ID_KEY = "function_id"
DISPLAY_NAME_KEY = "display_name"
QUERY_KEY = "query"
ETAG_KEY = "etag"

DEFAULT_TRIGGER_NAME = "When_a_response_to_an_Azure_Sentinel_alert_is_triggered"


class OperationType(Enum):
    ACTION = "action"
    ALERT_RULE = "alert_rule"
    WORKFLOW = "workflow"
    SAVED_SEARCH = "saved_search"


class ResourceType(Enum):
    SCHEDULED_DETECTION = "scheduled_detection"
    MICROSOFT_SECURITY_DETECTION = "microsoft_security_detection"
    DATA_SOURCE = "data_source"


class ResourceConfig(Enum):
    SCHEMA = "schema"
    TEMPLATE = "template"
    DOCUMENTATION = "documentation"


class ResourceFetchMethod(Enum):
    LOCAL = "local"
    FALLBACK = "fallback"


RESOURCE_DEFAULTS = {
    ResourceType.SCHEDULED_DETECTION: {
        ResourceConfig.SCHEMA: {
            ResourceFetchMethod.LOCAL: LOCAL_DETECTION_SCHEMA,
            ResourceFetchMethod.FALLBACK: DEFAULT_DETECTION_SCHEMA,
        },
        ResourceConfig.TEMPLATE: {
            ResourceFetchMethod.LOCAL: LOCAL_DETECTION_TEMPLATE,
            ResourceFetchMethod.FALLBACK: DEFAULT_DETECTION_TEMPLATE,
        },
        ResourceConfig.DOCUMENTATION: {
            ResourceFetchMethod.LOCAL: LOCAL_DETECTION_DOCUMENTATION,
            ResourceFetchMethod.FALLBACK: DEFAULT_DETECTION_DOCUMENTATION,
        },
    },
    ResourceType.DATA_SOURCE: {
        ResourceConfig.SCHEMA: {
            ResourceFetchMethod.LOCAL: LOCAL_DATA_SOURCE_SCHEMA,
            ResourceFetchMethod.FALLBACK: DEFAULT_DATA_SOURCE_SCHEMA,
        },
        ResourceConfig.TEMPLATE: {
            ResourceFetchMethod.LOCAL: LOCAL_DATA_SOURCE_TEMPLATE,
            ResourceFetchMethod.FALLBACK: DEFAULT_DATA_SOURCE_TEMPLATE,
        },
        ResourceConfig.DOCUMENTATION: {
            ResourceFetchMethod.LOCAL: LOCAL_DATA_SOURCE_DOCUMENTATION,
            ResourceFetchMethod.FALLBACK: DEFAULT_DATA_SOURCE_DOCUMENTATION,
        },
    },
    ResourceType.MICROSOFT_SECURITY_DETECTION: {
        ResourceConfig.SCHEMA: {
            ResourceFetchMethod.LOCAL: LOCAL_MICROSOFT_SECURITY_DETECTION_SCHEMA,
            ResourceFetchMethod.FALLBACK: DEFAULT_MICROSOFT_SECURITY_DETECTION_SCHEMA,
        },
        ResourceConfig.TEMPLATE: {
            ResourceFetchMethod.LOCAL: LOCAL_MICROSOFT_SECURITY_DETECTION_TEMPLATE,
            ResourceFetchMethod.FALLBACK: DEFAULT_MICROSOFT_SECURITY_DETECTION_TEMPLATE,
        },
        ResourceConfig.DOCUMENTATION: {
            ResourceFetchMethod.LOCAL: LOCAL_MICROSOFT_SECURITY_DETECTION_DOCUMENTATION,
            ResourceFetchMethod.FALLBACK: DEFAULT_MICROSOFT_SECURITY_DETECTION_DOCUMENTATION,
        },
    },
}
