# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ThreatIntelligenceMetric(Model):
    """Describes threat intelligence metric.

    :param last_updated_time_utc: Time Metric
    :type last_updated_time_utc: str
    :param threat_type_metrics: Threat type metrics
    :type threat_type_metrics:
     list[~securityinsights.models.ThreatIntelligenceMetricEntity]
    :param pattern_type_metrics: Pattern type metrics
    :type pattern_type_metrics:
     list[~securityinsights.models.ThreatIntelligenceMetricEntity]
    :param source_metrics: Source metrics
    :type source_metrics:
     list[~securityinsights.models.ThreatIntelligenceMetricEntity]
    """

    _attribute_map = {
        'last_updated_time_utc': {'key': 'lastUpdatedTimeUtc', 'type': 'str'},
        'threat_type_metrics': {'key': 'threatTypeMetrics', 'type': '[ThreatIntelligenceMetricEntity]'},
        'pattern_type_metrics': {'key': 'patternTypeMetrics', 'type': '[ThreatIntelligenceMetricEntity]'},
        'source_metrics': {'key': 'sourceMetrics', 'type': '[ThreatIntelligenceMetricEntity]'},
    }

    def __init__(self, *, last_updated_time_utc: str=None, threat_type_metrics=None, pattern_type_metrics=None, source_metrics=None, **kwargs) -> None:
        super(ThreatIntelligenceMetric, self).__init__(**kwargs)
        self.last_updated_time_utc = last_updated_time_utc
        self.threat_type_metrics = threat_type_metrics
        self.pattern_type_metrics = pattern_type_metrics
        self.source_metrics = source_metrics
