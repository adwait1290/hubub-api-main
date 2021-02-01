
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa


class AccountTag(BaseModel):
    __tablename__ = 'account_tag'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    account_id = sa.Column(sa.String, sa.ForeignKey('account.id', ondelete='CASCADE'))
    key = sa.Column('key', sa.String)
    value = sa.Column('value', sa.String)

class AccountTagSchema(ModelSchema):
    account_id = fields.String(required=False)
    key = fields.String(required=True)
    value = fields.String(required=False, missing=None)

    class Meta:
        model = AccountTag
        sqla_session = Session
        strict = False