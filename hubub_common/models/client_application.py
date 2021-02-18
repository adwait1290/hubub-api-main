import sqlalchemy as sa

import uuid

from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel
from .db import Session

def CreateClientID():
    return str(uuid.uuid4())


class ClientApplication(BaseModel):
    __tablename__="client_application"
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    name = sa.Column(sa.String, nullable=False)
    application_base_url=sa.Column(sa.String, nullable=False)
    application_public_key=sa.Column(sa.String,nullable=False)
    server_public_key = sa.Column(sa.String, nullable=False)
    server_private_key = sa.Column(sa.String, nullable=False)
    css_url=sa.Column(sa.String, nullable=True, default="")
    client_token=sa.Column(sa.String, nullable=False, default=CreateClientID())


class ClientApplicationSchema(ModelSchema):
    id = fields.Integer(required=False)
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
