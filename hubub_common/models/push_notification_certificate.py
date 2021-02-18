from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel
from .db import Session
from ._types import DeviceType

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )
from marshmallow import post_load, pre_load, post_dump, validate, fields
from sqlalchemy.orm import relationship


class PushNotificationCertificate(BaseModel):
    __tablename__ = 'push_notification_certificate'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    # type = sa.Column(ChoiceType(DeviceType, impl=sa.String()))
    label = sa.Column(sa.String)
    apns_certificate_uri = sa.Column(sa.String)
    use_apns_sandbox = sa.Column(sa.Boolean, server_default=false())
    fcm_key = sa.Column(sa.String)

    @post_load
    def make_pnc(self, data):
        return PushNotificationCertificate(**data)

class PushNotificationCertificateSchema(ModelSchema):
    __tablename__ = 'push_notification_certificate'
    id = fields.Integer(required=False)
    # type = fields.String(required=False,
    #                      validate=validate.OneOf(list(map(lambda x: x.value, DeviceType))))
    label = fields.String(required=False)
    apns_certificate_uri = fields.String(required=False)
    use_apns_sandbox = fields.Boolean(default=False)
    fcm_key = fields.String(required=False)

    class Meta:
        model = PushNotificationCertificate
        sqla_session = Session
        strict = False