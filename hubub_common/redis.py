# -*- coding: utf-8 -*-

import asyncio
import aioredis
import enum
import logging
from sqlalchemy.engine.url import make_url
from concurrent.futures import TimeoutError, CancelledError


__all__ = (
    'redisset',
    'redisget',
    'redisdel',
    'RedisDatabase'
)


class RedisDatabase(enum.Enum):
    General = 0
    DeviceRegistration = 1
    Authentication = 2
    IDP = 3
    Session = 5


async def redisset(app, redis_key, redis_value, database):
    if database == RedisDatabase.General:
        db = RedisDatabase.General.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_GENERAL")
    elif database == RedisDatabase.Authentication:
        db = RedisDatabase.Authentication.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_AUTHENTICATION")
    elif database == RedisDatabase.DeviceRegistration:
        db = RedisDatabase.DeviceRegistration.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_REGISTRATION")
    elif database == RedisDatabase.IDP:
        db = RedisDatabase.IDP.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_GENERAL")
    elif database == RedisDatabase.Session:
        db = RedisDatabase.Session.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_GENERAL")
    conf = make_url(app.hububconfig.get('REDIS_URL'))
    conn = await aioredis.create_connection((conf.host, conf.port), password=conf.password, db=int(db))
    try:
        await conn.execute('set', redis_key, redis_value)
        await conn.execute('expire', redis_key, timeout)
        status = True
    except:
        logging.getLogger()('could not set redis_key {} with value {}'
                   .format(redis_key, redis_value))
        status = False

    conn.close()
    await conn.wait_closed()

    return status


async def redisget(app, redis_key, database):
    if database == RedisDatabase.General:
        db = RedisDatabase.General.value
    elif database == RedisDatabase.Authentication:
        db = RedisDatabase.Authentication.value
    elif database == RedisDatabase.DeviceRegistration:
        db = RedisDatabase.DeviceRegistration.value
    elif database == RedisDatabase.IDP:
        db = RedisDatabase.IDP.value
    elif database == RedisDatabase.Session:
        db = RedisDatabase.Session.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_GENERAL")
    conf = make_url(app.hububconfig.get('REDIS_URL'))
    conn = await aioredis.create_connection((conf.host, conf.port), password=conf.password, db=int(db))

    value = None

    try:
        value = await conn.execute('get', redis_key)
        logging.getLogger().info('got value {} from redis.'.format(value))
    except:
        logging.getLogger().info("Could not get the key with value={}".format(redis_key))
        value = None
    conn.close()
    await conn.wait_closed()
    return value


async def redisdel(app, redis_key, database):
    if database == RedisDatabase.General:
        db = RedisDatabase.General.value
    elif database == RedisDatabase.Authentication:
        db = RedisDatabase.Authentication.value
    elif database == RedisDatabase.DeviceRegistration:
        db = RedisDatabase.DeviceRegistration.value
    elif database == RedisDatabase.IDP:
        db = RedisDatabase.IDP.value
        timeout = app.hububconfig.get("REDIS_TIMEOUT_GENERAL")
    conf = make_url(app.hububconfig.get('REDIS_URL'))
    conn = await aioredis.create_connection((conf.host, conf.port), password=conf.password, db=int(db))

    try:
        await conn.execute('del', redis_key)
        status = True
    except:
        logging.getLogger()('could not delete key: '
                   .format(redis_key))
        status = False

    conn.close()
    await conn.wait_closed()

    return status