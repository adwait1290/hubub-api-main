from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema

from .base import BaseModel

from .db import Session

import sqlalchemy as sa


class DetailedHubImage(BaseModel):
    __tablename__ = 'detailedhub_image'
    one_to_one = True
    detailedhub_id = sa.Column(sa.ForeignKey('detailedhub.id', ondelete='CASCADE'),
                               unique=False)
    image_id = sa.Column(sa.ForeignKey('image.id', ondelete='CASCADE'),
                         unique=True)


class DetailedHubImage(ModelSchema):
    id = fields.Integer(required=False)
    detailedhub_id = fields.Integer(required=True)
    image_id = fields.Integer(required=True)

    class Meta:
        model = DetailedHubImage
        sqla_session = Session
        strict = False
