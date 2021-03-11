import base64
import json
import logging
from typing import List

import boto3 as boto3
from boto.file import Key
from boto.s3.connection import S3Connection
from botocore.exceptions import ClientError

from hubub_common.redis import redisget, redisdel, redisset, RedisDatabase

from hubub_common.util import (
    generate_secret_key
)


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
    if app.hububconfig.get("IGNORE_SERVICE_CREDENTIALS"):
        return 'client_id', 'client_secret'

    assert user_id is not None
    aws_access_key = app.hububconfig.get('aws_access_key')
    assert aws_access_key is not None

    aws_secret_key = app.hububconfig.get('aws_secret_key')
    assert aws_secret_key is not None

    conn = S3Connection(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    bucket_name = app.hububconfig.get('S3_FACIAL_IMAGES_BUCKET_NAME')
    assert bucket_name is not None
    bucket = conn.get_bucket(bucket_name)
    for image in images:
        filename = '/'.join([
            app.hububconfig.get('S3_FACIAL_PREFIX'),
            '/'.join([str(user_id)]),
            '.'.join([generate_secret_key(64), encoding])
        ])
        k = Key(bucket, filename)
        image = base64.b64decode(image)
        k.set_contents_from_string(image)
    path = '/'.join([
        app.hububconfig.get('S3_FACIAL_PREFIX'),
        '/'.join([str(user_id)])])

    return path


def upload_single_image_to_s3(app, user_id, image: str, encoding: str) -> (str, str):
    """

    :param app: Current Servoce
    :param user_id: (int) User.id
    :param images_path: (str) Path for images. <user_id>/<images_path>/[images]
    :param images: List of images
    :param encoding: (str) encoding for images
    :return: (str) Path to the images
    """
    app.logger.info("Create Image Hit")
    assert user_id is not None
    aws_access_key = app.hububconfig.get('aws_access_key')
    assert aws_access_key is not None

    aws_secret_key = app.hububconfig.get('aws_secret_key')
    assert aws_secret_key is not None
    app.logger.info("Image S3 Connection about to him")
    session = boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    s3 = session.client("s3")
    bucket_name = app.hububconfig.get('S3_IMAGES_BUCKET_NAME')
    assert bucket_name is not None
    filename = '/' + app.hububconfig.get('S3_IMAGE_PREFIX') + \
               '/' + str(user_id) + '/' + generate_secret_key(64) + '.' + encoding
    app.logger.info("FileName for S3 Upload : {}".format(filename))
    image = base64.b64decode(image)
    try:
        response = s3.upload_file(filename, bucket_name, image)
        app.logger.info("Response from S3 Upload : {}".format(response))
    except ClientError as e:
        app.logger.warn("ClientError on S3 Upload: {}".format(e))
        return None, None
    except Exception as e:
        app.logger.warn("Exception on S3 Upload: {}".format(e))
    finally:
        path = bucket_name + filename
    app.logger.info("S3 path = {}".format(path))
    return path, filename
