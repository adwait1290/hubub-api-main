
import json
import logging

from sanic.response import json as sanic_response_json

from hubub_common.redis import redisget, redisdel, redisset, RedisDatabase

from hubub_common.exceptions import InvalidValueException
from hubub_common.util import (
    generate_secret_key
)

from hubub_common.models import (
    User
)


async def get_validation_data(request, auth_request_id):
    logging.getLogger().info("Waiting for identification result for auth_request_id={}"
                    .format(auth_request_id))
    resp = await redisget(request.app, auth_request_id, RedisDatabase.Authentication)

    if resp:
        data = resp.decode('utf-8')
        return data, 200
    else:
        return None, 400


async def get_validation_status(request, auth_request_id, validation_secret):
    server_validation_secret = await get_validation_secret(request, auth_request_id)
    logging.getLogger().warn("SERVER VALIDATION SECRET = {0} AND PROVIDED VALIATION SECRET = {1}".format(server_validation_secret, validation_secret))

    if validation_secret != server_validation_secret:
        logging.getLogger().warn("Stored and received secrets are not equal.")
        raise InvalidValueException("validation_secret")
        return False

    logging.getLogger().info("Stored and received secrets are equal.")
    status = await redisdel(request.app, auth_request_id, RedisDatabase.Authentication)

    if status:
        return True

    return False


async def make_authentication_status_secret(request, auth_request_id, validation_data_secret):
    logging.getLogger().info("Got request with auth_request_id={}"
                            .format(auth_request_id))
    authentication_status_secret = generate_secret_key()
    auth_status = await redisset(request.app, auth_request_id, authentication_status_secret, RedisDatabase.Authentication)
    validation_status = await redisset(request.app, auth_request_id, validation_data_secret, RedisDatabase.Session)

    if auth_status and validation_status:
        return sanic_response_json({
            'authentication_status_secret': authentication_status_secret,
            'validation_data_secret': validation_data_secret
        })
    elif auth_status == None:
        return sanic_response_json({
            'could not set authentication status secret':'failed'
        })
    elif validation_status == None:
        return sanic_response_json({
            'could not set validation data secret':'failed'
        })

async def get_validation_secret(request, auth_request_id):

    encoded_data = await redisget(request.app, auth_request_id, RedisDatabase.Authentication)

    if encoded_data is None:
        logging.getLogger().warn("Validation secret key for auth_request_id={} not found."
                                .format(auth_request_id))
        raise InvalidValueException("auth_request_id")

    escaped_data = encoded_data.decode("utf-8")
    string_data = str.strip(escaped_data)
    data = json.loads(string_data)
    validation = json.loads(data['validation'])
    return validation['validation_secret']
