import config.base

SERVICE_NAME = "Main Service"

SQLALCHEMY_DATABASE_URI = "postgres://dnqaegxogutpou:118836a3721f7f599847a52736e03faf2f30dcab1813fed89a047a945fa814c9@ec2-54-211-55-24.compute-1.amazonaws.com:5432/dd3ptlt7l9mgtd"
# DEVOPS_DATABASE_URI =
# REDIS_URL =

FRONTEND_DEFAULT_URL = "https://dashboard.dev.hubub.net"
GEO_SERVICE_BASE_URL = "https://geo.hubub.net"
IDENTIFICATION_PUSH_NOTIFICATION_BASE_URL = "https://identification.dev.hubub.net"

PUSH_NOTIFICATION_CERTIFICATE = 3

S3_CREDENTIALS_BUCKET_NAME = "hubub-credentials"
S3_CREDENTIALS_FILE_NAME = "dev/authentication-services"

PUSH_NOTIFICATION_CERT_IOS_DEFAULT = 3
PUSH_NOTIFICATION_CERT_MACOS_DEFAULT = 5
PUSH_NOTIFICATION_CERT_WIN_DEFAULT = 8

RECREATE_SCHEMA = False
HMAC_EXPIRATION = 300
VALIDATION_PREFIX_LENGTH=3
RUN_SERVICE_ON_PORT = 5551
DEBUG_SERVICE = False
PRESERVE_CONTEXT_ON_EXCEPTION = False
ASSETS_DEBUG = True
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'

EXPIRE_TOKEN_HOURS = 24
REDIS_TIMEOUT_GENERAL = 60*60*24
REDIS_TIMEOUT_REGISTRATION = 60*60*24
REDIS_TIMEOUT_AUTHENTICATION = 60*60*24

BLUETOOTH_SERVICE_IDENTIFIER_LENGTH = 32
BLUETOOTH_ONLY_SERVICE_IDENTIFIER_LENGTH = 25
VALIDATION_SERVER_TOKEN_LENGTH = 48

PROXIMITY_TIMEOUT_WALKAWAY = 30     # seconds
PROXIMITY_TIMEOUT_CLOSE = 300        # seconds
PROXIMITY_DEFAULT_POWER = -48
PROXIMITY_RSSI_RANGE = 20

AUTHENTICATION_TIMEOUT_SECONDS = 40

SECRET_KEY = 'cd15c9878c061b5492eb44897fa95cbf78bbf606c3eb81d785beda009097c097'

aws_access_key = "AKIAJEJEG42DJP5EIOIQ"
aws_secret_key = "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"

INCLUDE_DEBUG_ROUTES = True

