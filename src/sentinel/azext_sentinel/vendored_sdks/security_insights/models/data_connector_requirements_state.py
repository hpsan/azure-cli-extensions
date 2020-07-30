# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DataConnectorRequirementsState(Model):
    """Data connector requirements status.

    :param authorization_state: Authorization state for this connector.
     Possible values include: 'Valid', 'Invalid'
    :type authorization_state: str or
     ~securityinsights.models.DataConnectorAuthorizationState
    :param license_state: License state for this connector. Possible values
     include: 'Valid', 'Invalid', 'Unknown'
    :type license_state: str or
     ~securityinsights.models.DataConnectorLicenseState
    """

    _attribute_map = {
        'authorization_state': {'key': 'authorizationState', 'type': 'str'},
        'license_state': {'key': 'licenseState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DataConnectorRequirementsState, self).__init__(**kwargs)
        self.authorization_state = kwargs.get('authorization_state', None)
        self.license_state = kwargs.get('license_state', None)