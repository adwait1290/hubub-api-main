import base64
import hashlib
import logging
import os
import random
import time
import hmac
import re

from cryptography.fernet import Fernet
from functools import wraps
from itertools import islice
from string import ascii_letters, digits
from sys import byteorder
from os import urandom
from sanic.response import json as sanic_response_json

from marshmallow.compat import iteritems

from hubub_common.redis import *

from hubub_common.exceptions import InvalidParameterException

from .exceptions import InvalidCredentialsException, ExpiredCredentialsException, BaseAuthenticationException, BaseHTTPException


class Headers():
    def __init__(self, request):
        self.request = request

    async def verify(self):

        verified = False

        try:
            auth_request_id = self.request.headers['authentication'].split(' ')[-1][
                              0:self.request.headers['authentication'].split(' ')[-1].find(":")]

            encoded_data = await redisget(self.request.app, auth_request_id, RedisDatabase.Session)

            if (encoded_data):
                escaped_data = encoded_data.decode("utf-8")
                validation_data_secret = str.strip(escaped_data)
            else:
                logging.getLogger().warn(
                    "Could not get validation_data_secret with auth_request_id={}".format(auth_request_id))
                return False
        except Exception as e:
            logging.getLogger().warn(
                "Could not get validation_data_secret with auth_request_id={}".format(auth_request_id))
            return False

        verified, clientid = verify_authentication_headers(self.request.app, self.request.headers, validation_data_secret, self.request.url)

        return verified


def async_validate_strict_schema(schema):
    def decorator(func):
        @wraps(func)
        async def wrapper(resource, request, **kwargs):
            schema_fields = [
                field_obj.load_from or argname
                for argname, field_obj in iteritems(schema.fields)
            ]
            if request.body:
                request_data = request.json
            else:
                request_data = {}

            for key in request_data.keys():
                if key not in schema_fields:
                    logging.getLogger().warn(
                        "[VALIDATE SCHEMA]: Got a request body {} with unexpected {} attribute. "
                        "Expected fields are: {}".format(request_data, key, schema_fields))
                    raise InvalidParameterException(key)

            return func(resource, request, **kwargs)

        return wrapper
    return decorator


def handle_authentication_headers_errors(err):
    """ Checks does the response errors contain any authentication headers related errors.
    If so raise 401 Unauthorised error.

    :param err: errors dictionary
    :raises 401: if errors dictionary contains headers related errors
    :return:
    """
    authentication_failed_args = [
        'X-Hubub-Authentication-Timestamp',
        'X-Hubub-Authentication-Version',
        'Authentication'
    ]

    authentication_headers_errors = [
        (arg, err.messages[arg])
        for arg in authentication_failed_args if arg in err.field_names
        ]

    if authentication_headers_errors:
        raise BaseAuthenticationException(
            status_code=401,
            status='missing_credentials',
            description='Credentials not available in headers'
        )


def make_authentication_headers(client_id: str, client_shared_secret: str, request_uri: str) -> dict:
    """ Makes a dictionary with authentication headers (used across all the services)
    using given secret keys.

    :param client_id:
    :param client_shared_secret:
    :param request_uri: URI that was used for encoding
    :return: headers dictionary
    """
    token, timestamp = encode_auth_token(client_id, client_shared_secret, request_uri)
    return {
        'Authentication': token,
        'X-Hubub-Authentication-Timestamp': str(timestamp),
        'X-Hubub-Authentication-Version': '1'
    }


def verify_authentication_headers(current_app , headers: dict, secret: str, request_uri=None) -> (bool, str):
    """ Verifies were the request headers encoded correctly using given secret key.

    :param headers: headers dictionary
    :param secret: secret key that was used for encoding
    :param request_uri: URI that was used for encoding
    :param expiration_time: time delta for validation timestamp
    :raise 401: passed headers are invalid
    :return: (bool, str, dict): verified, client_id
    """
    timestamp = headers['x-Hubub-authentication-timestamp']
    try:
        token_type, token = headers['authentication'].split(' ')
    except ValueError:
        token_type, token = headers['authentication'], ''
    request_uri = request_uri or current_app.request.url
    request_url = re.sub(r'.*://', '', request_uri)

    current_app.logger.info(
        "[VERIFY AUTH HEADERS]: Verifying authentication headers={} for request_uri={} with secret={}"
        .format(headers, request_url, secret))

    if token_type != 'hmac':
        current_app.logger.warn(
            "[VERIFY AUTH HEADERS]: Authentication token has wrong type ({}). hmac is expected."
            .format(token_type))
        raise InvalidCredentialsException()

    expiration_time = current_app.hububconfig.get('HMAC_EXPIRATION')

    #verify_token_expiration(timestamp, expiration_time)
    current_app.logger.info("Attempting to verify token:{} with timestamp:{}, request_url:{} and secret:{}"
                            .format(token,timestamp,request_url,secret))
    verified, client_id = verify_auth_token(token, timestamp, request_url, secret)

    return verified, client_id


def verify_token_expiration(timestamp, expiration_time):
    current_timestamp = int(time.time())
    timestamp = int(timestamp)

    if abs(current_timestamp - timestamp) > expiration_time:
        raise ExpiredCredentialsException()


def from_pyfile(filename, silent=False):
    filename = os.path.join(filename)
    config = {}
    try:
        with open(filename) as config_file:
            exec(compile(config_file.read(), filename, 'exec'), config)
    except IOError as exc:
        if silent and exc.errno in ('ENOENT', 'EISDIR'):
            return {}

        exc.strerror = 'Unable to load configuration file ({})'.format(exc.strerror)
        raise exc

    return config

def generate_secret_key(bits=192):
    """ Generates random created 192-bit key.

    :param bits: desired key length in bits
    :return: generated key
    """
    assert bits % 8 == 0
    bytes_ = os.urandom(bits // 8)

    hex_ = '%032x' % int.from_bytes(bytes_, byteorder='big')
    return str(hex_).upper().lstrip('0')


def generate_random_chars(size):
    chars = []

    for item in ''.join([ascii_letters, digits]):
        chars.append(item)

    selection = iter(lambda: random.choice(chars), object())
    return ''.join(islice(selection, size))


def create_one_time_use_token(client_shared_secret: str) -> str:
    nonce = str(int.from_bytes(os.urandom(8), byteorder))
    key = ''.join(str(item) for item in [nonce, client_shared_secret])
    token_256 = hashlib.sha256(key.encode()).digest()
    token = token_256[:16]
    return base64.b64encode(token).decode('utf-8')


def check_for_http_exception(self):
    http_error_msg = ''
    reason = self.json_data

    if 400 <= self.status_code < 500:
        http_error_msg = u'%s Client Error: %s for url: %s' % (self.status_code, reason, self.url)

    elif 500 <= self.status_code < 600:
        http_error_msg = u'%s Server Error: %s for url: %s' % (self.status_code, reason, self.url)

    if http_error_msg:
        raise BaseHTTPException(reason)


def handle_request_parsing_error(err):
    handle_authentication_headers_errors(err)
    raise BaseHTTPException(
        err.messages,
        status='missing_required_parameter',
        status_code=400)


def make_request():
    #define generic requests call here
    return True


def encode_auth_token(client_id: str, client_shared_secret: str, request_uri: str) -> (str, str):
    request_url = re.sub(r'.*://', '', request_uri)
    nonce = str(int.from_bytes(urandom(8), byteorder))
    key = ''.join([nonce, client_shared_secret])
    token_256 = hashlib.sha256(key.encode()).digest()
    token = token_256[:16]

    timestamp = int(time.time())
    key = ''.join([nonce, request_url, str(timestamp)])
    digest_256 = hmac.new(token, msg=key.encode(), digestmod=hashlib.sha256).digest()
    digest = digest_256[:16]

    signature = base64.b64encode(digest)

    return 'hmac {0}'.format(':'.join([client_id, nonce, signature.decode('ascii')])), timestamp


def verify_auth_token(token: str, timestamp: int, request_uri: str, client_shared_secret: str) -> (bool, str):
    request_url = re.sub(r'.*://', '', request_uri)
    try:
        client_id, nonce, signature = token.split(':')
    except ValueError:
        return False, None

    if client_id.startswith('hmac'):
        client_id = client_id.split(' ')[-1]

    key = ''.join(str(item) for item in [nonce, client_shared_secret])
    token_256 = hashlib.sha256(key.encode()).digest()
    token = token_256[:16]

    key = ''.join([nonce, request_url, str(timestamp)])
    digest_256 = hmac.new(token, msg=key.encode(), digestmod=hashlib.sha256).digest()
    digest = digest_256[:16]

    new_signature = base64.b64encode(digest).decode()

    return new_signature == signature, client_id


def encrypt_token(app, device_id, client_id, shared_secret, salt):
    secret = shared_secret[0:16].encode()
    key = b''.join([salt.encode(),secret])

    try:
        encryption_key = ''.join(base64.urlsafe_b64encode(key).decode())
        cipher = Fernet(encryption_key)
        payload = str(device_id).encode()
        encrypted_token = cipher.encrypt(payload)
        encoded_salt = base64.b64encode(salt.encode()).decode()
        timestamp = int(time.time())
        return ' {0}'.format(':'.join([str(client_id), str(encoded_salt), encrypted_token.decode('ascii'),str(timestamp)]))
    except Exception as e:
        logging.getLogger().info("Exception saving service provider{}".e)
        logging.getLogger().warn("Token is expired")
        return None


def decrypt_token(request, encrypted_token, shared_secret):

    try:
        client_id, salt, encoded_token, timestamp = encrypted_token.decode().split(":")
        a = 1
    except ValueError:
        return False, None
    logging.getLogger().info(str(client_id), str(salt), str(encoded_token))
    try:
        verify_token_expiration(timestamp, request.app.hububconfig.get("TOKEN_INVALIDATION_TIMEOUT"))
    except Exception as e:
        logging.getLogger().warn("token is expired EXCEPTION:{}".format(e))
        return None
    decoded_salt = base64.b64decode(salt.encode())
    clean_token = encoded_token.encode()
    secret = shared_secret[0:16].encode()
    key = b''.join([decoded_salt,secret])
    encryption_key = base64.urlsafe_b64encode(key)
    cipher = Fernet(encryption_key)
    decrypted_token = cipher.decrypt(encoded_token.encode(), ttl=20000)
    final_token = decrypted_token.decode()
    return final_token


def decrypt_expired_token(request, encrypted_token, shared_secret):
    try:
        client_id, salt, encoded_token, timestamp = encrypted_token.decode().split(":")
    except ValueError:
        return False, None

    decoded_salt = base64.b64decode(salt.encode())
    clean_token = encoded_token.encode()
    secret = shared_secret[0:16].encode()
    key = b''.join([decoded_salt,secret])
    encryption_key = base64.urlsafe_b64encode(key)
    cipher = Fernet(encryption_key)
    decrypted_token = cipher.decrypt(encoded_token.encode(), ttl=20000)
    final_token = decrypted_token.decode()
    return final_token