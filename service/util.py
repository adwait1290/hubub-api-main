import base64
import json
import logging

from boto.file import Key
from boto.s3.connection import S3Connection
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


def upload_images_to_s3(app, user_id, images: List[str], encoding: str) -> str:
    """

    :param app: Current Servoce
    :param user_id: (int) User.id
    :param images_path: (str) Path for images. <user_id>/<images_path>/[images]
    :param images: List of images
    :param encoding: (str) encoding for images
    :return: (str) Path to the images
    """

    logging.getLogger().info("Got {0} images for user:{1}".format(len(images), user_id))
    if app.sonikpassconfig.get("IGNORE_SERVICE_CREDENTIALS"):
        return 'client_id', 'client_secret'

    assert user_id is not None
    aws_access_key = app.sonikpassconfig.get('aws_access_key')
    assert aws_access_key is not None

    aws_secret_key = app.sonikpassconfig.get('aws_secret_key')
    assert aws_secret_key is not None

    conn = S3Connection(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    bucket_name = app.sonikpassconfig.get('S3_FACIAL_IMAGES_BUCKET_NAME')
    assert bucket_name is not None
    bucket = conn.get_bucket(bucket_name)
    for image in images:
        filename = '/'.join([
            app.sonikpassconfig.get('S3_FACIAL_PREFIX'),
            '/'.join([str(user_id)]),
            '.'.join([generate_secret_key(64), encoding])
        ])
        k = Key(bucket, filename)
        image = base64.b64decode(image)
        k.set_contents_from_string(image)
    path = '/'.join([
        app.sonikpassconfig.get('S3_FACIAL_PREFIX'),
        '/'.join([str(user_id)])])

    return path


def upload_single_image_to_s3(app, user_id, image: str, encoding: str) -> (str,str):
    """

    :param app: Current Servoce
    :param user_id: (int) User.id
    :param images_path: (str) Path for images. <user_id>/<images_path>/[images]
    :param images: List of images
    :param encoding: (str) encoding for images
    :return: (str) Path to the images
    """
    assert user_id is not None
    aws_access_key = app.sonikpassconfig.get('aws_access_key')
    assert aws_access_key is not None

    aws_secret_key = app.sonikpassconfig.get('aws_secret_key')
    assert aws_secret_key is not None

    conn = S3Connection(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    bucket_name = app.sonikpassconfig.get('S3_IMAGES_BUCKET_NAME')
    assert bucket_name is not None
    bucket = conn.get_bucket(bucket_name)
    filename = '/'.join(
        app.hububappconfig.get('HUBUB_IMAGE_PREFIX'),
        '/'.join([str(user_id)]),
        '.'.join([generate_secret_key(64), encoding]))

    k = Key(bucket, filename)
    image = base64.b64decode(image)
    k.set_contents_from_string(image)
    path = '/'.join([
        app.sonikpassconfig.get('S3_IMAGE_PREFIX'),
        '/'.join([str(user_id)])])

    return path, filename
