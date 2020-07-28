# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class IncidentComment(Resource):
    """Represents an incident comment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar created_time_utc: The time the comment was created
    :vartype created_time_utc: datetime
    :param message: Required. The comment message
    :type message: str
    :ivar author: Describes the client that created the comment
    :vartype author: ~securityinsights.models.ClientInfo
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_time_utc': {'readonly': True},
        'message': {'required': True},
        'author': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created_time_utc': {'key': 'properties.createdTimeUtc', 'type': 'iso-8601'},
        'message': {'key': 'properties.message', 'type': 'str'},
        'author': {'key': 'properties.author', 'type': 'ClientInfo'},
    }

    def __init__(self, **kwargs):
        super(IncidentComment, self).__init__(**kwargs)
        self.created_time_utc = None
        self.message = kwargs.get('message', None)
        self.author = None
