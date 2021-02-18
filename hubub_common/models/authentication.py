
import enum

from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from marshmallow import fields, pre_load, Schema, validates_schema, validate



class AuthenticationResult(enum.Enum):
    allowed = 1
    denied = 2
    failed = 3


class AuthenticationStatus(enum.Enum):
    started = 1
    notification_sent = 2
    identification_requested = 3
    validation_requested = 4
    completed = 5
    identification_started = 6
    identification_confirmed = 7


class AuthenticationSessionStatus(enum.Enum):
    active = 1
    inactive = 2
    expired = 3
    verifying = 4
    closed = 5
    idle = 6
    walkaway = 7


class AuthenticationMethod(enum.Enum):
    manual = 1
    bluetooth = 2
    geolocation = 3
    sonic = 4
    facial = 5
    validation_server = 6


class Authentication(BaseModel):
    __tablename__ = 'authentication'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    auth_request_id = sa.Column(sa.String)
    authentication_status = sa.Column(
        sa.Enum(*[value for value, _ in AuthenticationStatus.__members__.items()],
                name="authentication_status_enum")
    )
    authentication_result = sa.Column(
        sa.Enum(*[value for value, _ in AuthenticationResult.__members__.items()],
                name="authentication_result_enum")
    )
    authentication_session_status = sa.Column(
        sa.Enum(*[value for value, _ in AuthenticationSessionStatus.__members__.items()],
                name="authentication_session_status_enum")
    )
    authentication_method = sa.Column(
        sa.Enum(*[value for value, _ in AuthenticationMethod.__members__.items()],
                name="authentication_method_enum")
    )
    authentication_status_secret = sa.Column(sa.String)
    app_version = sa.Column(sa.String)
    devices = sa.Column(sa.String)
    browser_device = sa.Column(sa.String)
    mobile_device = sa.Column(sa.String)
    desktop_device = sa.Column(sa.String)

    browser = sa.Column(sa.String)
    os = sa.Column(sa.String)
    useragent = sa.Column(sa.String)

    ipaddress = sa.Column(sa.String)
    port = sa.Column(sa.Integer)
    geolocation = sa.Column(sa.String)

    ble_mobile = sa.Column(sa.String)
    ble_desktop = sa.Column(sa.String)
    walkaway_data = sa.Column(sa.String)

    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    push_notification_certificate_id = sa.Column(sa.Integer, sa.ForeignKey('push_notification_certificate.id'))
    logged_in_at = sa.Column(sa.DateTime, nullable=True, server_default=None)
    logged_out_at = sa.Column(sa.DateTime, nullable=True, server_default=None)
    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)


class AuthenticationSchema(ModelSchema):
    id = fields.Integer(dump_only=True)
    auth_request_id = fields.String(required=True)
    authentication_result = fields.String(required=False, validate=validate.OneOf(list(map(lambda x: x.value, AuthenticationResult))))
    authentication_status = fields.String(required=False, validate=validate.OneOf(list(map(lambda x: x.value, AuthenticationStatus))))
    authentication_session_status = fields.String(required=False, validate=validate.OneOf(list(map(lambda x: x.value, AuthenticationSessionStatus))))
    authentication_method = fields.String(required=False, validate=validate.OneOf(list(map(lambda x: x.value, AuthenticationMethod))))
    browser_device = fields.String(required=False)
    mobile_device = fields.String(required=False)
    desktop_device = fields.String(required=False)
    authentication_status_secret = fields.String(required=False)
    app_version = fields.String(required=False)
    browser = fields.String(required=False)
    os = fields.String(required=False)
    useragent = fields.String(required=False)

    ipaddress = fields.String(required=False)
    port = fields.Integer(required=False)
    geolocation = fields.String(required=False)

    ble_mobile = fields.String(required=False)
    ble_desktop = fields.String(required=False)
    walkaway_data = fields.String(required=False)

    user_id = fields.Integer(required=False)
    push_notification_certificate_id = fields.Integer(required=False)
    logged_in_at = fields.DateTime(required=False)
    logged_out_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    created_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = Authentication
        sqla_session = Session
        strict = False


class BaseStrictSchema(Schema):
    @pre_load
    def handle_authentication_header(self, data):
        # TODO temporary solution for handling headers with lowercase
        authentication = data.pop('authentication', None)
        if authentication is not None:
            data['Authentication'] = authentication


class AuthenticationHeadersSchema(ModelSchema):
    # headers
    authentication = fields.String(
        required=True,
        location='headers',
        load_from='authentication')

    authentication_timestamp = fields.String(
        required=True,
        location='headers',
        load_from='x-hubub-authentication-timestamp')

    authentication_version = fields.String(
        required=True,
        location='headers',
        load_from='x-hubub-authentication-version')

    # @pre_load
    # def handle_timestamp(self, data):
    #     timestamp = data.get('x-hubub-authentication-timestamp')
    #     # TODO temporary solution for handling android service headers
    #     if timestamp and timestamp.isdigit():
    #         data['x-hubub-authentication-timestamp'] = int(timestamp)

    class Meta:
        sqla_session = Session
        strict = False


class AuthenticationDataSchema(AuthenticationHeadersSchema):
    requested_data = fields.Dict(required=False, missing={})
    validation = fields.Dict(required=False, missing={})
    communication = fields.Dict(required=False, missing={})

    class Meta:
        sqla_session = Session
        strict = False


class AuthenticationStatusSchema(Schema):
    authentication_status_secret = fields.String(required=True)

    class Meta:
        sqla_session = Session
        strict = False


class AuthenticationLoginSchema(Schema):
    requested_data = fields.Dict(required=False, missing=None)
    validation = fields.Dict(required=False, missing=None)
    communication = fields.Dict(required=False, missing=None)

    class Meta:
        sqla_session = Session
        strict = False

