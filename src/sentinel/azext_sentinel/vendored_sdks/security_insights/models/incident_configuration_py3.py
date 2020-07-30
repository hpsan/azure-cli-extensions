# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class IncidentConfiguration(Model):
    """Incident Configuration property bag.

    All required parameters must be populated in order to send to Azure.

    :param create_incident: Required. Create incidents from alerts triggered
     by this analytics rule
    :type create_incident: bool
    :param grouping_configuration: Set how the alerts that are triggered by
     this analytics rule, are grouped into incidents
    :type grouping_configuration:
     ~securityinsights.models.GroupingConfiguration
    """

    _validation = {
        'create_incident': {'required': True},
    }

    _attribute_map = {
        'create_incident': {'key': 'createIncident', 'type': 'bool'},
        'grouping_configuration': {'key': 'groupingConfiguration', 'type': 'GroupingConfiguration'},
    }

    def __init__(self, *, create_incident: bool, grouping_configuration=None, **kwargs) -> None:
        super(IncidentConfiguration, self).__init__(**kwargs)
        self.create_incident = create_incident
        self.grouping_configuration = grouping_configuration