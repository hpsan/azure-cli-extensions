# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ThreatIntelligenceMetricEntity(Model):
    """Describes threat intelligence metric entity.

    :param metric_name: Metric name
    :type metric_name: str
    :param metric_value: Metric value
    :type metric_value: int
    """

    _attribute_map = {
        'metric_name': {'key': 'metricName', 'type': 'str'},
        'metric_value': {'key': 'metricValue', 'type': 'int'},
    }

    def __init__(self, *, metric_name: str=None, metric_value: int=None, **kwargs) -> None:
        super(ThreatIntelligenceMetricEntity, self).__init__(**kwargs)
        self.metric_name = metric_name
        self.metric_value = metric_value
