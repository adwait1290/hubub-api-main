
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa


class ContactPostalAddress(BaseModel):
    __tablename__ = 'contact_postal_address'
    many_to_many = True
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    contact_id = sa.Column(sa.ForeignKey('contact.id', ondelete='CASCADE'))
    postal_address_id = sa.Column(sa.ForeignKey('postal_address.id', ondelete='CASCADE'))

    def __init__(self, id, contact_id, postal_address_id):
        self.id = id
        self.contact_id = contact_id
        self.postal_address_id = postal_address_id

class ContactPostalAddressSchema(ModelSchema):
    id = fields.Integer(dump_only=True)
    contact_id = fields.String(dump_only=True)
    postal_address_id = fields.String(dump_only=True)

    class Meta:
        model = ContactPostalAddress
        sqla_session = Session
        strict = False