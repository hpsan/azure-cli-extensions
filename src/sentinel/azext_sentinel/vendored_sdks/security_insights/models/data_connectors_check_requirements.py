# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DataConnectorsCheckRequirements(Model):
    """Data connector requirements properties.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AADCheckRequirements, AATPCheckRequirements,
    ASCCheckRequirements, AwsCloudTrailCheckRequirements,
    MCASCheckRequirements, MDATPCheckRequirements, TICheckRequirements,
    TiTaxiiCheckRequirements

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'AzureActiveDirectory': 'AADCheckRequirements', 'AzureAdvancedThreatProtection': 'AATPCheckRequirements', 'AzureSecurityCenter': 'ASCCheckRequirements', 'AmazonWebServicesCloudTrail': 'AwsCloudTrailCheckRequirements', 'MicrosoftCloudAppSecurity': 'MCASCheckRequirements', 'MicrosoftDefenderAdvancedThreatProtection': 'MDATPCheckRequirements', 'ThreatIntelligence': 'TICheckRequirements', 'ThreatIntelligenceTaxii': 'TiTaxiiCheckRequirements'}
    }

    def __init__(self, **kwargs):
        super(DataConnectorsCheckRequirements, self).__init__(**kwargs)
        self.kind = None
