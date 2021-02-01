
from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )

from sqlalchemy.orm import relationship


class UserFacialModel(BaseModel):
    __tablename__ = 'user_facial_model'
    id = sa.Column(sa.Integer, primary_key=True, nullable=False)
    user_id = sa.Column(sa.ForeignKey('user.id'))
    facial_model_id = sa.Column(sa.ForeignKey('facial_model.id'))


class UserFacialModelSchema(ModelSchema):
    id = fields.Integer(required=False)
    user_id = fields.Integer(required=True)
    facial_model_id = fields.Integer(required=True)

    class Meta:
        model = UserFacialModel
        sqla_session = Session
        strict = False

