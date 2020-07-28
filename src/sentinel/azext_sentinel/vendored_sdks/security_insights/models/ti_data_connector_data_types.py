# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class TIDataConnectorDataTypes(Model):
    """The available data types for TI (Threat Intelligence) data connector.

    :param indicators: Data type for indicators connection.
    :type indicators:
     ~securityinsights.models.TIDataConnectorDataTypesIndicators
    """

    _attribute_map = {
        'indicators': {'key': 'indicators', 'type': 'TIDataConnectorDataTypesIndicators'},
    }

    def __init__(self, **kwargs):
        super(TIDataConnectorDataTypes, self).__init__(**kwargs)
        self.indicators = kwargs.get('indicators', None)
