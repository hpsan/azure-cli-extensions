from pathlib import Path

DEFAULT_DETECTION_SCHEMA: Path = Path(__file__).parent / 'default_detection_schema.yaml'
DOCUMENTATION_TEMPLATE: Path = Path(__file__).parent / 'detection_documentation_template.md'

# Default value for generating new detections
DEFAULT_DETECTION_TEMPLATE: str = """
id: {}

# The period (in ISO 8601 duration format) that this detection looks at
query_frequency: P1D

# Add query period in ISO 8601 duration format
query_period: P1D

# The severity for alerts created by this detection
# Options: Informational, Low, Medium, High
severity: Low

# The operation against the threshold that triggers detection
# Options: GreaterThan, LessThan, Equal, NotEqual
trigger_operator: 'GreaterThan'

# The threshold triggers this detection
trigger_threshold: 0

# The description of this detection
description: |
  '{}'

# The display name for this detection
display_name: '{}'

# Determines whether this detection is enabled or disabled
enabled: True

# The tactics for this detection
# Options: InitialAccess, Execution, Persistence, PrivilegeEscalation, DefenseEvasion, CredentialAccess, Discovery,
#          LateralMovement, Collection, Exfiltration, CommandAndControl, Impact
tactics:
  - # Add tactics here

# The suppression (in ISO 8601 duration format) to wait since last time this detection been triggered
suppression_duration: 'P10D'

# Determines whether the suppression for this detection is enabled or disabled
suppression_enabled: True

# The KQL query that creates alerts for this detection
# Read aka.ms/kql to learn how to write KQL queries
# Also see tips and tricks here https://github.com/Azure/Azure-Sentinel/wiki/Gotcha%27s-when-building-queries
query: |
  SecurityEvent
  | limit 10
"""
