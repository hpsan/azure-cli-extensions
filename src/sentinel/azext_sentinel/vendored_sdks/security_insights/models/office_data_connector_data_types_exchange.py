# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .data_connector_data_type_common import DataConnectorDataTypeCommon


class OfficeDataConnectorDataTypesExchange(DataConnectorDataTypeCommon):
    """Exchange data type connection.

    :param state: Describe whether this data type connection is enabled or
     not. Possible values include: 'Enabled', 'Disabled'
    :type state: str or ~securityinsights.models.DataTypeState
    """

    _attribute_map = {
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OfficeDataConnectorDataTypesExchange, self).__init__(**kwargs)
