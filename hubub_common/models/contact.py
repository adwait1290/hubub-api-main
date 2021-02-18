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


class Contact(BaseModel):
    __tablename__ = 'contact'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    firstname = sa.Column(sa.String)
    lastname = sa.Column(sa.String)
    is_account_contact = sa.Column(sa.Boolean)
    email = relationship("Email", secondary="contact_email",
                            backref="email", cascade="all,delete-orphan", single_parent=True)

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)


class ContactSchema(ModelSchema):
    id = fields.Integer(dump_only=True)
    firstname = fields.String(required=True)
    lastname = fields.String(required=False, missing=None)
    is_account_contact = fields.Boolean(required=False, default=False)
    email = fields.Nested('EmailSchema', many=True, required=False, missing=[])

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = Contact
        sqla_session = Session
        strict = False