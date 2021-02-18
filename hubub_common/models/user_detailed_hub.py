from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel
from .base import BaseModel, ModelSchema, fields


from .db import Session

import sqlalchemy as sa


class UserDetailedHub(BaseModel):
    __tablename__ = 'user_detailed_hub'
    one_to_many = True
    user_id = sa.Column(sa.ForeignKey('user_id', ondelete='CASCADE'),
        unique=False)
    detailed_hub_id = sa.Column(sa.ForeignKey('detailed_hub_id', ondelete='CASCADE'),
        unique=False)


class UserDetailedHubScema(ModelSchema):
    id = fields.Integer(required=False)
    user_id = fields.Integer(required=True)
    user_detailed_hub_id = fields.Integer(required=True)

    class Meta:
        model = UserDetailedHub
        sqla_session = Session
        strict = False
