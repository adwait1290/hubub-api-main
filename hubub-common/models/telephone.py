
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa


class Telephone(BaseModel):
    __tablename__ = 'telephone'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    label = sa.Column(sa.String)
    country_code = sa.Column(sa.String)
    number = sa.Column(sa.String, nullable=False)


class TelephoneSchema(ModelSchema):
    label = fields.String(required=False, missing=None)
    country_code = fields.String(required=False)
    number = fields.String(required=True)

    class Meta:
        model = Telephone
        sqla_session = Session
        strict = False
