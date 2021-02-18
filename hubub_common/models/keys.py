from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa

from ._types import KeysStatus

from sqlalchemy import (
        func
    )

class Keys(BaseModel):
    __tablename__ = 'keys'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    private_key = sa.Column(sa.String)
    public_key = sa.Column(sa.String)
    keys_status = sa.Column(
        sa.Enum(*[value for value, _ in KeysStatus.__members__.items()], name="keys_status_enum")
    )
    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)
    invalidated_at = sa.Column(sa.DateTime, nullable=True, server_default=None)


class KeysSchema(ModelSchema):
    id = fields.Integer(required=False)
    private_key = fields.String(required=False)
    public_key = fields.String(required=False)
    keys_status = fields.Integer(required=False)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)
    invalidated_at = fields.DateTime(required=False)

    class Meta:
        model = Keys
        sqla_session = Session
        strict = False