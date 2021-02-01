import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

import uuid

from .base import BaseModel, ModelSchema, fields
from .db import Session

def CreateClientID():
    return str(uuid.uuid4())


class ClientApplication(BaseModel):
    __tablename__="client_application"
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    account_id = sa.Column(sa.ForeignKey('account.id'))
    name = sa.Column(sa.String, nullable=False)
    application_base_url=sa.Column(sa.String, nullable=False)
    application_public_key=sa.Column(sa.String,nullable=False)
    server_public_key = sa.Column(sa.String, nullable=False)
    server_private_key = sa.Column(sa.String, nullable=False)
    css_url=sa.Column(sa.String, nullable=True, default="")
    client_token=sa.Column(sa.String, nullable=False, default=CreateClientID())


class ClientApplicationSchema(ModelSchema):
    id = fields.Integer(required=False)
    account = fields.Nested('AccountSchema', many=False, required=False, missing=None)
    name = fields.String(required=False)
    application_base_url = fields.String(required=False)
    application_public_key = fields.String(required=False)
    server_public_key = fields.String(required=False)
    server_private_key = fields.String(required=False)
    css_url = fields.String(required=False)
    client_token = fields.String(required=False)

    class Meta:
        model = ClientApplication
        sqla_session = Session
        strict = False
