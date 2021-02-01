
from enum import Enum
from .base import BaseModel, ModelSchema, fields
from .db import Session
from .user_device import *
from ._types import DeviceType, RegistrationStatus

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )
from sqlalchemy_utils import ChoiceType
from marshmallow import post_load, pre_load, post_dump, validate


class Device(BaseModel):
    __tablename__ = 'device'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    label = sa.Column(sa.String)
    type = sa.Column(ChoiceType(DeviceType, impl=sa.String()))
    registration_status = sa.Column(
        sa.Enum(*[value for value, _ in RegistrationStatus.__members__.items()], name="registration_status_enum")
    )
    device_id = sa.Column(sa.String)
    secret = sa.Column(sa.String)
    push_notification_token = sa.Column(sa.String)
    app_version = sa.Column(sa.String)
    keystore = sa.Column(sa.String)
    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)
    service_credentials = sa.Column(sa.DateTime, nullable=True, server_default=None)
    push_notification_certificate = relationship("PushNotificationCertificate")
    push_notification_certificate_id = sa.Column(sa.Integer, sa.ForeignKey('push_notification_certificate.id'),
                                                 nullable=True)
    @post_load
    def make_device(self, data):
        return Device(**data)


class DeviceSchema(ModelSchema):
    id = fields.Integer(required=False)
    label = fields.String(required=False)
    type = fields.String(required=False,
                         validate=validate.OneOf(list(map(lambda x: x.value, DeviceType))))
    registration_status = fields.Integer(required=False)
    device_id = fields.String(required=True)
    secret = fields.String(required=True)
    push_notification_token = fields.String(required=False)
    app_version = fields.String(required=False)
    keystore = fields.String(required=False)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)
    service_credentials = fields.DateTime(required=False)
    push_notification_certificate_id = fields.Integer(required=False)

    class Meta:
        model = Device
        sqla_session = Session
        strict = False