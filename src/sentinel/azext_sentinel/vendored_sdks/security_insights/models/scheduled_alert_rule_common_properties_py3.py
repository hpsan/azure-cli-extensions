# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ScheduledAlertRuleCommonProperties(Model):
    """Schedule alert rule template property bag.

    :param query: The query that creates alerts for this rule.
    :type query: str
    :param query_frequency: The frequency (in ISO 8601 duration format) for
     this alert rule to run.
    :type query_frequency: timedelta
    :param query_period: The period (in ISO 8601 duration format) that this
     alert rule looks at.
    :type query_period: timedelta
    :param severity: The severity for alerts created by this alert rule.
     Possible values include: 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~securityinsights.models.AlertSeverity
    :param trigger_operator: The operation against the threshold that triggers
     alert rule. Possible values include: 'GreaterThan', 'LessThan', 'Equal',
     'NotEqual'
    :type trigger_operator: str or ~securityinsights.models.TriggerOperator
    :param trigger_threshold: The threshold triggers this alert rule.
    :type trigger_threshold: int
    :param event_grouping_settings: The event grouping settings.
    :type event_grouping_settings:
     ~securityinsights.models.EventGroupingSettings
    """

    _attribute_map = {
        'query': {'key': 'query', 'type': 'str'},
        'query_frequency': {'key': 'queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'queryPeriod', 'type': 'duration'},
        'severity': {'key': 'severity', 'type': 'str'},
        'trigger_operator': {'key': 'triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'triggerThreshold', 'type': 'int'},
        'event_grouping_settings': {'key': 'eventGroupingSettings', 'type': 'EventGroupingSettings'},
    }

    def __init__(self, *, query: str=None, query_frequency=None, query_period=None, severity=None, trigger_operator=None, trigger_threshold: int=None, event_grouping_settings=None, **kwargs) -> None:
        super(ScheduledAlertRuleCommonProperties, self).__init__(**kwargs)
        self.query = query
        self.query_frequency = query_frequency
        self.query_period = query_period
        self.severity = severity
        self.trigger_operator = trigger_operator
        self.trigger_threshold = trigger_threshold
        self.event_grouping_settings = event_grouping_settings
