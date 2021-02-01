
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa


class PostalAddress(BaseModel):
    __tablename__ = 'postal_address'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    label = sa.Column(sa.String)
    address_1 = sa.Column(sa.String, nullable=False)
    address_2 = sa.Column(sa.String)
    region = sa.Column(sa.String, nullable=False)
    postal_code = sa.Column(sa.String)
    country = sa.Column(sa.String, nullable=False)


class PostalAddressSchema(ModelSchema):
    label = fields.String(required=False, missing=None)
    address_1 = fields.String(required=True)
    address_2 = fields.String(required=False, missing=None)
    region = fields.String(required=True)
    postal_code = fields.String(required=False, missing=None)
    country = fields.String(required=True)

    class Meta:
        model = PostalAddress
        sqla_session = Session
        strict = False