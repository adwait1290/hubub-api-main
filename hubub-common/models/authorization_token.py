import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

import uuid

from .base import BaseModel, ModelSchema, fields
from .db import Session


def CreateToken():
    return str(uuid.uuid4())


class AuthorizationToken(BaseModel):
    __tablename__="authorization_token"
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    application_id = sa.Column(sa.ForeignKey('client_application.id'))
    access_token = sa.Column(sa.String, nullable=False, default=CreateToken())
    authorization_code =sa.Column(sa.String, nullable=False, default=CreateToken())


class AuthorizationTokenSchema(ModelSchema):
    id = fields.Integer(required=False)
    application_id = fields.Nested('ClientApplicationSchema', many=False, required=False, missing=None)
    access_token = fields.String(required=False)
    authorization_code = fields.String(required=False)

    class Meta:
        model = AuthorizationToken
        sqla_session = Session
        strict = False
