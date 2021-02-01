
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship


class UserGroupServiceProvider(BaseModel):
    __tablename__ = 'user_group_service_provider'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    group_id = sa.Column(sa.Integer, sa.ForeignKey('group.id'))
    service_provider_id = sa.Column(sa.Integer, sa.ForeignKey('service_provider.id'))

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

class UserGroupServiceProviderSchema(ModelSchema):
    id = fields.Integer(required=False)
    user_id = fields.Integer(required=False)
    group_id = fields.Integer(required=False)
    service_provider_id = fields.Integer(required=False)

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = UserGroupServiceProvider
        sqla_session = Session
        strict = False