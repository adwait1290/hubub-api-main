from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship


class ServiceProvider(BaseModel):
    __tablename__ = 'service_provider'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    logo_url = sa.Column(sa.String)
    authentication_url = sa.Column(sa.String, unique=True)

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

class ServiceProviderSchema(ModelSchema):
    id = fields.Integer(required=False)
    logo_url = fields.String(required=False)
    authentication_url = fields.String(required=False)

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = ServiceProvider
        sqla_session = Session
        strict = False