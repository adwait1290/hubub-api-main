from sqlalchemy import func

from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from marshmallow import post_load

from .base import BaseModel
from .db import Session


import sqlalchemy as sa


class Image(BaseModel):
    __tablename__ = 'image'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    image_key = sa.Column(sa.String, nullable=False)
    image_name = sa.Column(sa.String, nullable=True)
    image_path = sa.Column(sa.String, nullable=True)
    image_encoding = sa.Column(sa.String, nullable=True)
    image_url = sa.Column(sa.String, nullable=True)
    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

    @post_load
    def make_image(self, data):
        return Image(**data)


class ImageSchema(ModelSchema):
    id = fields.Integer(required=False)
    image_key = fields.String(required=True)
    image_name = fields.String(required=True)
    image_path = fields.String(required=True)
    image_encoding = fields.String(required=True)
    image_url = fields.String(required=True)
    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = Image
        sqla_session = Session
        strict = False