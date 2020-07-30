# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .data_connectors_check_requirements_py3 import DataConnectorsCheckRequirements


class TICheckRequirements(DataConnectorsCheckRequirements):
    """Represents threat intelligence requirements check request.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param tenant_id: The tenant id to connect to, and get the data from.
    :type tenant_id: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
    }

    def __init__(self, *, tenant_id: str=None, **kwargs) -> None:
        super(TICheckRequirements, self).__init__(**kwargs)
        self.tenant_id = tenant_id
        self.kind = 'ThreatIntelligence'