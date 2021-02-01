
from .base import BaseModel, ModelSchema, fields
from enum import Enum
from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship

class UserRegistrationStatus(Enum):
    started = 1
    email_sent = 2
    email_verified = 3
    completed = 4
    admin_disable = 5
    user_disable = 6
    account_cancelled = 7
    expired = 8
    deleted = 9


class User(BaseModel):
    __tablename__ = 'user'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    username = sa.Column(sa.String, nullable=False)
    user_registration_status = sa.Column(
        sa.Enum(*[value for value, _ in UserRegistrationStatus.__members__.items()], name ="user_registration_status_enum")
    )
    contact = relationship("Contact")
    contact_id = sa.Column(sa.ForeignKey('contact.id', ondelete='CASCADE'))

    account_id = sa.Column(sa.ForeignKey('account.id', ondelete='CASCADE'))

    is_primary = sa.Column(sa.Boolean, default=False)
    has_facial_images = sa.Column(sa.Boolean, default=False)
    facial_storage_prefix = sa.Column(sa.String, nullable=True)

    idtoken = sa.Column(sa.String)
    secret1 = sa.Column(sa.String)
    secret2 = sa.Column(sa.String)

    tags = relationship("UserTag", backref="user", uselist=True, lazy="dynamic")


    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

    __table_args__ = (
        UniqueConstraint('username', 'account_id', name='account_id_username_key'),
    )


class UserSchema(ModelSchema):
    id = fields.Integer(required=False)
    username = fields.String(required=True)

    is_primary = fields.Boolean(required=False)
    has_facial_images = fields.Boolean(required=False)
    user_registration_status = fields.String(required=False)
    idtoken = sa.Column(sa.String)
    secret1 = sa.Column(sa.String)
    secret2 = sa.Column(sa.String)

    contact = fields.Nested('ContactSchema', many=False, required=False, missing=None)
    account = fields.Nested('AccountSchema', many=False, required=False, missing=None)
    tags = fields.Nested('UserTagSchema', many=True, required=False, missing=[])
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = User
        sqla_session = Session
        strict = False
