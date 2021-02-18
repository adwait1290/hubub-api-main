from enum import Enum

from marshmallow import post_load, fields
from marshmallow_sqlalchemy import ModelSchema
from sqlalchemy import func

from .base import BaseModel
from .db import Session
from marshmallow import post_load

from .base import BaseModel
from .db import Session


import sqlalchemy as sa


class SimpleHub(BaseModel):
    __tablename__ = 'SimpleHub'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    title = sa.Column(sa.String, nullable=True)
    is_published = sa.Column(sa.Boolean, default=False)
    hub_url = sa.Column(sa.String, nullable=True)
    image_url = sa.Column(sa.String, nullable=True)
    order = sa.Column(sa.Integer, default=0)
    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

    @post_load
    def make_simple_hub(self, data):
        return SimpleHub(**data)


class SimpleHubSchema(ModelSchema):
    id = fields.Integer(required=False)
    title = fields.String(required=False)
    is_published = fields.Boolean(required=True)
    hub_url = fields.String(required=False)
    image_url = fields.String(required=False)
    order = fields.Integer(required=True)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = SimpleHub
        sqla_session = Session
        strict = False