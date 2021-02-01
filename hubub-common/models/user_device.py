
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship


class UserDevice(BaseModel):
    __tablename__ = 'user_device'
    many_to_many = True

    user_id = sa.Column(
        sa.ForeignKey('user.id', ondelete='CASCADE'),
        unique=False)
    device_id = sa.Column(
        sa.ForeignKey('device.id', ondelete='CASCADE'),
        unique=False)


class UserDeviceSchema(ModelSchema):
    id = fields.Integer(required=False)
    user_id = fields.Integer(required=True)
    device_id = fields.Integer(required=True)

    class Meta:
        model = UserDevice
        sqla_session = Session
        strict = False