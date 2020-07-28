# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class EntityExpandResponse(Model):
    """The entity expansion result operation response.

    :param meta_data: The metadata from the expansion operation results.
    :type meta_data: ~securityinsights.models.ExpansionResultsMetadata
    :param value: The expansion result values.
    :type value: ~securityinsights.models.EntityExpandResponseValue
    """

    _attribute_map = {
        'meta_data': {'key': 'metaData', 'type': 'ExpansionResultsMetadata'},
        'value': {'key': 'value', 'type': 'EntityExpandResponseValue'},
    }

    def __init__(self, **kwargs):
        super(EntityExpandResponse, self).__init__(**kwargs)
        self.meta_data = kwargs.get('meta_data', None)
        self.value = kwargs.get('value', None)
