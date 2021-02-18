from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa


class Email(BaseModel):
    __tablename__ = 'email'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    label = sa.Column(sa.String, server_default="Default")
    emailaddress = sa.Column(sa.String, nullable=False)

class EmailSchema(ModelSchema):
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    label = fields.String(required=False, missing=None)
    emailaddress = fields.String(required=True)

    class Meta:
        model = Email
        sqla_session = Session
        strict = False

