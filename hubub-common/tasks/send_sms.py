import boto3
import boto.sns as sns
import jinja2

from jinja2_s3loader import S3loader

from celery import Celery
from celery.utils.log import get_task_logger

taskrunner = Celery()


logger = get_task_logger(__name__)


@taskrunner.task(name='send_sms', bind=True, max_retries=10, rate_limit='1000/s')
def send_sms(self, messages) -> None:
    client = boto3.client('sns', region_name='us-east-1', aws_access_key_id=self._app.hububconfig.get('aws_access_key'), aws_secret_access_key=self._app.hububconfig.get('aws_secret_key'))
    s3 = boto3.client('s3', region_name='us-east-1', aws_access_key_id=self._app.hububconfig.get('aws_access_key'), aws_secret_access_key=self._app.hububconfig.get('aws_secret_key'))
    logger.info('BUCKETNAME: ' + self._app.hububconfig.get('S3_SMS_TEMPLATE_BUCKET_NAME') + "TEMPLATE_FOLDER: " + self._app.hububconfig.get('S3_REGISTRATION_TEMPLATE_BODY_SMS_FOLDER') )
    j2 = jinja2.Environment(
        loader=S3loader(
            self._app.hububconfig.get('S3_SMS_TEMPLATE_BUCKET_NAME'),
            self._app.hububconfig.get('S3_REGISTRATION_TEMPLATE_BODY_SMS_FOLDER'),
            s3=s3
        )
    )

    for message in messages:
        logger.info("LOGGING THE TEMPLATE NAME: " + message['sms_body']['body']['text_path'])
        template = j2.get_template(message['sms_body']['body']['text_path'])
        body = template.render(**message['sms_body']['parameters'])

        recipients = message['sms_headers']['to']
        subject = message['sms_headers']['subject']

        for recipient in recipients:
            logger.info("Sending a message to {}".format(recipient))
            response = client.publish(
                PhoneNumber=recipient,
                Message=body,
                Subject=subject,
            )
            logger.info("Received a response from SNS - {}".format(response))