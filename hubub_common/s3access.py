# # -*- coding: utf-8 -*-
#
# import json
# import boto
# import tempfile
#
# from boto.s3.key import Key
#
# __all__ = (
#     'get_service_credentials',
#     'get_mc_account_credentials',
#     'get_certificate'
# )
#
#
# def get_service_credentials(app, service_name: str) -> (str, str):
#     """ Reads credentials file on S3 storage and returns actual
#     client ID and secret key for given service name.
#
#     :param app: current app
#     :param service_name: service which credentials are needed
#     :return:
#     """
#
#     if app.hububconfig.get("IGNORE_SERVICE_CREDENTIALS"):
#         return 'client_id', "client_secret"
#
#     bucket_name = app.hububconfig.get('S3_CREDENTIALS_BUCKET_NAME')
#     assert bucket_name is not None
#
#     credentials_filename = app.hububconfig.get('S3_CREDENTIALS_FILE_NAME')
#     assert credentials_filename is not None
#
#     conn = boto.connect_s3(app.hububconfig.get('aws_access_key'), app.hububconfig.get('aws_secret_key'), is_secure=False)
#     bucket = conn.get_bucket(bucket_name, validate=False)
#
#     k = Key(bucket, credentials_filename)
#     credentials = k.get_contents_as_string().decode("utf-8") or "{}"
#     service_credentials = json.loads(credentials).get(service_name)
#
#     return (
#         service_credentials.get("client_id"),
#         service_credentials.get("secret")
#     )
#
# def get_mc_account_credentials(app):
#     """ Reads credentials file on S3 storage and returns actual
#        client ID and secret key for given service name.
#
#        :param app: current app
#        :param service_name: service which credentials are needed
#        :return:
#        """
#     if app.hububconfig.get("IGNORE_SERVICE_CREDENTIALS"):
#         return 'client_id', "client_secret"
#
#     bucket_name = app.hububconfig.get('S3_CREDENTIALS_BUCKET_NAME')
#     assert bucket_name is not None
#
#     credentials_filename = app.hububconfig.get('S3_CONSOLE_CREDENTIALS_FILENAME')
#     assert credentials_filename is not None
#
#     conn = boto.connect_s3(app.hububconfig.get('aws_access_key'), app.hububconfig.get('aws_secret_key'),
#                            is_secure=False)
#     bucket = conn.get_bucket(bucket_name, validate=False)
#
#     k = Key(bucket, credentials_filename)
#     credentials = k.get_contents_as_string().decode("utf-8") or "{}"
#     service_credentials = json.loads(credentials)
#
#     return (
#         service_credentials.get("client_id"),
#         service_credentials.get("secret")
#     )
#
#
# """ Connects to the S3 bucket to open and read credentials file. """
# def get_certificate(app, filename: str) -> (str, str):
#
#     bucket_name = app.hububconfig.get('S3_CONFIG_BUCKET_NAME')
#     assert bucket_name is not None
#
#     conn = boto.connect_s3(app.hububconfig.get('aws_access_key'), app.hububconfig.get('aws_secret_key'), is_secure=False)
#     bucket = conn.get_bucket(bucket_name, validate=False)
#
#     fp = tempfile.NamedTemporaryFile()
#
#     key = bucket.get_key(filename)
#     key.get_contents_to_file(fp)
#
#     fp.seek(0)
#
#     return fp