# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ThreatIntelligenceArmStixSortBy1(Model):
    """Describes an threat intelligence ARM STIX Sort By.

    :param item_key: Item key
    :type item_key: str
    :param sort_order: Sort order. Possible values include: 'unsorted',
     'ascending', 'descending'
    :type sort_order: str or
     ~securityinsights.models.ThreatIntelligenceArmStixSortBy
    """

    _attribute_map = {
        'item_key': {'key': 'itemKey', 'type': 'str'},
        'sort_order': {'key': 'sortOrder', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ThreatIntelligenceArmStixSortBy1, self).__init__(**kwargs)
        self.item_key = kwargs.get('item_key', None)
        self.sort_order = kwargs.get('sort_order', None)
