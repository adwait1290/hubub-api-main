# -*- coding: utf-8 -*-

import enum
from hubub_common.models.authentication import AuthenticationHeadersSchema

from marshmallow import fields, pre_load, Schema, validates_schema


class MethodType(enum.Enum):
    audio = 'audio'
    audio_bluetooth = 'audio_bluetooth'
    validation_server = 'validation_server'
    manual = 'manual'
    bluetooth = 'bluetooth'


class AuthenticationDataSchema(AuthenticationHeadersSchema):
    requested_data = fields.Dict(required=False, missing={})
    validation = fields.Dict(required=False, missing={})
    communication = fields.Dict(required=False, missing={})

    class Meta:
        strict = True


class AuthenticationRequestsSchema(AuthenticationHeadersSchema):
    username = fields.String(required=True)
    account_name = fields.String(required=True)
    client_api_id = fields.Integer(required=True)

    class Meta:
        strict = True


class AuthenticationStatusSchema(AuthenticationHeadersSchema):
    authentication_status_secret = fields.Str(required=True)

    class Meta:
        strict = True


class AuthenticationStatusServiceSchema(AuthenticationHeadersSchema):
    authentication_status_secret = fields.Str(required=True)

    class Meta:
        strict = True


class AuthenticationStatusStoreSchema(AuthenticationHeadersSchema):
    # data
    expire_in = fields.Int(required=False)

    class Meta:
        strict = True


class UrlShortenerSchema(AuthenticationHeadersSchema):
    long_url = fields.String(required=True)

    class Meta:
        strict = True


class AuthResourceSchema(Schema):

    account_name = fields.String(location='query', required=True)
    username = fields.String(location='query', required=True)

    class Meta:
        strict = True


class CheckTokenSchema(Schema):

    token = fields.String(location='query', required=True)

    class Meta:
        strict = True


class ExpireTokenSchema(Schema):
    token = fields.String(required=True)

    class Meta:
        strict = True
