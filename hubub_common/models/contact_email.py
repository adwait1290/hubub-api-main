from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa


class ContactEmail(BaseModel):
    __tablename__ = 'contact_email'
    many_to_many = True
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    contact_id = sa.Column(sa.ForeignKey('contact.id', ondelete='CASCADE'))
    email_id = sa.Column(sa.ForeignKey('email.id', ondelete='CASCADE'))

    def __init__(self, id, contact_id, email_id):
        self.id = id
        self.contact_id = contact_id
        self.email_id = email_id

class ContactEmailSchema(ModelSchema):
    id = fields.Integer(dump_only=True)
    contact_id = fields.String(dump_only=True)
    email_id = fields.String(dump_only=True)

    class Meta:
        model = ContactEmail
        sqla_session = Session
        strict = False