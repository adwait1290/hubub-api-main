# -*- coding: utf-8 -*-

import os
import sqlalchemy as sa

from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import orm
from sqlalchemy.pool import NullPool

from hubub_common.models.base import (
    BaseModel
)

__all__ = (
    'init_pg',
    'close_pg'
)

Session = orm.scoped_session(orm.sessionmaker())

async def init_pg(hububconfig, version, recreate_schema):

    conf = make_url(hububconfig.get('SQLALCHEMY_DATABASE_URI') + "_" + hububconfig.get('SERVICE_NAME') + "_V" + version + "_PID:" + str(os.getpid()))
    engine = sa.create_engine(conf, echo=False, poolclass=NullPool)
    Session = scoped_session(sessionmaker(bind=engine))

    if recreate_schema:
        BaseModel.metadata.drop_all(engine, checkfirst=True)
        BaseModel.metadata.create_all(engine, checkfirst=False)

        conn = engine.connect()
        conn.execute("INSERT INTO account_group(name) VALUES('admin')")
        conn.execute("INSERT INTO user_group(name) VALUES('admin')")
    else:
        BaseModel.metadata.create_all(engine, checkfirst=True)

    BaseModel.initialize(BaseModel,session=Session,engine=engine)

    return engine, Session


async def close_pg(service):
    service.engine.close()