# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class RelationNode(Model):
    """Relation node.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param relation_node_id: Relation Node Id
    :type relation_node_id: str
    :ivar relation_node_kind: The type of relation node. Possible values
     include: 'Case', 'Bookmark'
    :vartype relation_node_kind: str or
     ~securityinsights.models.RelationNodeKind
    :param etag: Etag for relation node
    :type etag: str
    :param relation_additional_properties: Additional set of properties
    :type relation_additional_properties: dict[str, str]
    """

    _validation = {
        'relation_node_kind': {'readonly': True},
    }

    _attribute_map = {
        'relation_node_id': {'key': 'relationNodeId', 'type': 'str'},
        'relation_node_kind': {'key': 'relationNodeKind', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'relation_additional_properties': {'key': 'relationAdditionalProperties', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(RelationNode, self).__init__(**kwargs)
        self.relation_node_id = kwargs.get('relation_node_id', None)
        self.relation_node_kind = None
        self.etag = kwargs.get('etag', None)
        self.relation_additional_properties = kwargs.get('relation_additional_properties', None)