
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa


class ContactTelephone(BaseModel):
    __tablename__ = 'contact_telephone'
    many_to_many = True
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    contact_id = sa.Column(sa.ForeignKey('contact.id', ondelete='CASCADE'))
    telephone_id = sa.Column(sa.ForeignKey('telephone.id', ondelete='CASCADE'))

    def __init__(self, id, contact_id, telephone_id):
        self.id = id
        self.contact_id = contact_id
        self.telephone_id = telephone_id

class ContactTelephoneSchema(ModelSchema):
    id = fields.Integer(dump_only=True)
    contact_id = fields.String(dump_only=True)
    telephone_id = fields.String(dump_only=True)

    class Meta:
        model = ContactTelephone
        sqla_session = Session
        strict = False