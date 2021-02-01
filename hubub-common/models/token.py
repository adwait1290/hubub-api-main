
import enum
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship


class TokenStatus(enum.Enum):
    new = 1
    inuse = 2
    expired = 3
    deleted = 4


class Token(BaseModel):
    __tablename__ = 'token'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    token_status = sa.Column(
        sa.Enum(*[value for value, _ in TokenStatus.__members__.items()], name='token_status_enum'))

    token = sa.Column(sa.String)
    user_id = sa.Column(
        sa.ForeignKey('user.id', ondelete='CASCADE'),
        unique=True)

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)


class TokenSchema(ModelSchema):
    id = fields.Integer(required=False)
    token_status = fields.Integer(required=False)

    token = sa.Column(sa.String)
    user_id = fields.Integer(required=False)

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = Token
        sqla_session = Session
        strict = False
