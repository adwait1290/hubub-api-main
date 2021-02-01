
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )


class AccountGroup(BaseModel):
    __tablename__ = 'account_group'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    name = sa.Column('name', sa.String)

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

class AccountGroupSchema(ModelSchema):
    name = fields.String(required=True)

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = AccountGroup
        sqla_session = Session
        strict = False