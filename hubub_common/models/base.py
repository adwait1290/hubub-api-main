

import sqlalchemy as sa

from sqlalchemy import orm

from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint,
        Boolean
    )
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_mixins import AllFeaturesMixin



Base = declarative_base()


class BaseModel(Base, AllFeaturesMixin):
    __abstract__ = True
    Session = orm.scoped_session(orm.sessionmaker())
    session = Session()

    id = sa.Column(Integer, primary_key=True)
    pass

    def initialize(self, session, engine):
        self.session = session
        self.engine = engine

def _get_all_subclasses(base_cls):
        return dict([(subclass.__tablename__, subclass)
                     for subclass in base_cls.__subclasses__()])


