from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa


class UserSimpleHub(BaseModel):
    __tablename__ = 'user_simplehub'
    one_to_many = True
    user_id = sa.Column(sa.ForeignKey('user.id', ondelete='CASCADE'),
                        unique=False)
    simplehub_id = sa.Column(sa.ForeignKey('simplehub.id', ondelete='CASCADE'),
                             unique=False)


class UserSimpleHubScema(ModelSchema):
    id = fields.Integer(required=False)
    user_id = fields.Integer(required=True)
    simplehub_id = fields.Integer(required=True)

    class Meta:
        model = UserSimpleHub
        sqla_session = Session
        strict = False
