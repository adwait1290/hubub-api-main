
import json
import logging
import os
import re
import requests
import urllib

from datetime import datetime
from time import sleep
from pushjack import APNSClient, APNSSandboxClient
from pushjack.exceptions import APNSInvalidTokenError, APNSInvalidPayloadSizeError, APNSMissingPayloadError
from pyfcm import FCMNotification
from pyfcm.errors import AuthenticationError, FCMServerError, InvalidDataError, InternalPackageError

from hubub_common.models import (
    AuthenticationStatus,
    Device,
    DeviceType,
    UserDevice,
    PushNotificationCertificate
)


async def send_android_push_notification(app, devicetype, message, data, push_notification_token, fcm_key):

    push_service = FCMNotification(api_key=fcm_key)
    logging.getLogger().info \
        ("Sending push notifications to {0} device: {1}".format(devicetype, push_notification_token))

    try:
        resp = push_service.notify_multiple_devices(
            registration_ids=push_notification_token,
            data_message=data
        )

    except (AuthenticationError, FCMServerError, InvalidDataError, InternalPackageError) as e:
        logging.getLogger().warn(
            "Failed to send push notifications to Android Device: {0} {1} with error {2}".
                format(devicetype, push_notification_token, e))

        return False

    return resp


async def send_apple_push_notification(app, devicetype, alert, data, push_notification_token, apns_certificate_uri, use_apns_sandbox, content_available=False):

    try:
        config_environment = os.environ['APP_CONFIG_FILE']
        logging.getLogger().info("Retrieved config file: " + config_environment)
    except Exception:
        logging.getLogger().info("Failed to retrieve config file: reverting to local.py")
        config_environment = "local.py"

    environment = re.sub(r'\.py', '', config_environment)
    file = None

    logging.getLogger().info("Environment: " + environment)

    file = apns_certificate_uri
    current_dir = os.path.abspath(os.curdir)
    certificate = os.path.join(current_dir, 'hubub_common', 'apple/%s' % file)

    logging.getLogger().info("current directory: " + current_dir + " :::.... certificate: " + certificate)

    if use_apns_sandbox:
        client = APNSSandboxClient(certificate=certificate)

    else:
        client = APNSClient(certificate=certificate)

    logging.getLogger().info("Sending push notifications to Apple Device {} with token: {}".format(devicetype, push_notification_token))

    try:
        if (alert):
            resp = client.send(
                push_notification_token,
                alert,
                extra=data,
                category='hububCATEGORY',
                error_timeout=0,
                sound="default",
                content_available=content_available
            )
        else:
            resp = client.send(
                push_notification_token,
                extra=data,
                error_timeout=0,
                content_available=content_available
            )
        logging.getLogger().info("RESPONSE FROM DEVICE WAS:{}".format(resp))

    except (
            APNSInvalidTokenError,
            APNSInvalidPayloadSizeError,
            APNSInvalidPayloadSizeError,
            APNSMissingPayloadError
    ) as e:
        logging.getLogger().warn(
            "Failed to send push notifications to Apple Device {} with token: {} with error {}".format(devicetype, push_notification_token, e))

        return False

    return resp


async def send_multiple_apple_push_notification(app, devicetype, alert, data, token_list, apns_certificate_uri, use_apns_sandbox,content_available=False):

    try:
        config_environment = os.environ['APP_CONFIG_FILE']
        logging.getLogger().info("Retrieved config file: " + config_environment)
    except Exception:
        logging.getLogger().info("Failed to retrieve config file: reverting to local.py")
        config_environment = "local.py"

    environment = re.sub(r'\.py', '', config_environment)
    file = None

    logging.getLogger().info("Environment: " + environment)

    file = apns_certificate_uri
    current_dir = os.path.abspath(os.curdir)
    certificate = os.path.join(current_dir, 'hubub_common', 'apple/%s' % file)

    logging.getLogger().info("current directory: " + current_dir + " :::.... certificate: " + certificate)

    if use_apns_sandbox:
        client = APNSSandboxClient(certificate=certificate)

    else:
        client = APNSClient(certificate=certificate)

    logging.getLogger().info \
        ("Sending push notifications to Apple Device of type: {} with token_list of {}".format(devicetype,
                                                                                                                   token_list))

    try:
        if (alert):
            resp = client.send(
                token_list,
                alert,
                extra=data,
                category='hububCATEGORY',
                error_timeout=0,
                sound="default",
                content_available=content_available
            )
        else:
            resp = client.send(
                token_list,
                extra=data,
                error_timeout=0,
                content_available=content_available
            )
        logging.getLogger().info("RESPONSE FROM APNS service WAS:{}".format(resp))

    except (
            APNSInvalidTokenError,
            APNSInvalidPayloadSizeError,
            APNSInvalidPayloadSizeError,
            APNSMissingPayloadError
    ) as e:
        logging.getLogger().warn(
            "Failed to send push notifications to Apple Device {} with tokens: {} with error {}".format(devicetype,
                                                                                                        token_list,
                                                                                                        e))

        return False

    return resp


async def get_access_token(app):

    live_url = "https://login.live.com/accesstoken.srf?"
    headers = dict()

    payload = {
        "grant_type": "client_credentials",
        "client_id": app.hububconfig.get('WPNS_client_id'),
        "client_secret": app.hububconfig.get('WPNS_client_secret'),
        "scope": "notify.windows.com"
    }

    data = urllib.parse.urlencode(payload)
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    headers['Content-Length'] = str(len(data))

    response = requests.post(url=live_url, headers=headers, data=data)
    if response.status_code == 200:

        response_data = json.loads(response.text)
        access_token = response_data['access_token']
        token_type = response_data['token_type']

        return access_token, token_type

    return None


async def send_windows_push_notification(app, data, push_notification_token, username, message_text, activate_text):

    access_token, token_type = await get_access_token(app)
    logging.getLogger().info("Got back access_token={0} and token_type={1}".format(access_token, token_type))
    launch = urllib.parse.urlencode(data)
    local_data = "<toast launch=\"notification?{0}\">" \
                 "<visual lang=\"en-US\">" \
                 "<binding template=\"ToastGeneric\">" \
                 "<text hint-maxLines=\"1\">{1}</text>" \
                 "<text>{2}</text>" \
                 "</binding>" \
                 "</visual>" \
                 "<actions>" \
                 "<action content=\"{3}\" arguments=\"notification?{4}\" activationType=\"foreground\"/>" \
                 "<action activationType=\"system\" arguments=\"dismiss\" content=\"\"/>" \
                 "</actions>" \
                 "</toast>".format(launch, message_text, username, activate_text, launch)

    headers = dict()
    headers['Authorization'] = "Bearer {}".format(access_token)
    headers['X-WNS-Type'] = "wns/toast"
    headers['X-WNS-RequestForStatus'] = "true"

    headers['Host'] = "cloud.notify.windows.com"
    headers['Content-Length'] = str(len(data))
    headers['X-WNS-TTL'] = "30"

    response = requests.post(url=push_notification_token, headers=headers, data=local_data)
    if response.status_code == 200:
        return True
    return False


def create_data_messages(auth_request_id, data, action, validation, identification_data_secret, requested_data):

    try:
        mobile_alert = {
            "title-loc-key": "NOTIFICATION_TITLE",
            "loc-key": "NOTIFICATION_BODY",
            "action-loc-key": "NOTIFICATION_ACCEPT_ACTION"
        }

        desktop_alert = {
            "title-loc-key": "Verified Presence® Request",
            "loc-key": "Click to Accept",
            "action-loc-key": "Accept"
        }

        geolocation_data = data.get('geolocation_data')
        user_id = str(data.get('user_id'))
        account_id = data.get('account_id')

        mobile_data_message = {
            'data': {
                "auth_request_id": auth_request_id,
                "action": action,
                "geolocation_data": geolocation_data,
                "user_id": user_id,
                "account_id": account_id
            }
        }

        desktop_data_message = {
            'data': {
                "auth_request_id": auth_request_id,
                "geolocation_data": geolocation_data,
                "user_id": user_id,
                "account_id": account_id,
                "validation_secret": validation['validation_secret'],
                "action": action,
                "timeout_seconds": 25
            }
        }

        if mobile_data_message["data"]["action"] == "identify":
            mobile_data_message["data"]["identify"] = {
                "identification_data_secret": identification_data_secret['identification_data_secret'],
                "requested_data": requested_data
            }

        if validation:
            mobile_data_message["data"]["validation"] = validation

            if "proximity" in requested_data:
                mobile_data_message["data"]["validation"].pop('validation_secret', None)

        if "proximity" in requested_data:
            desktop_data_message["data"]["service-id"] = requested_data["proximity"]["service-id"]
            desktop_data_message["data"]["characteristic-id"] = requested_data["proximity"]["characteristic-id"]
            # include the timeout
            if "timeout_seconds" in requested_data:
                desktop_data_message["data"]["timeout_seconds"] = requested_data["timeout_seconds"]

    except Exception as e:
        logging.getLogger().info("Exception creating push notification alerts: {}".format(e))

    return mobile_alert, desktop_alert, mobile_data_message, desktop_data_message


def create_session_messages(data):

    try:
        mobile_alert = {
            "title-loc-key": "NOTIFICATION_TITLE",
            "loc-key": "NOTIFICATION_BODY",
            "action-loc-key": "NOTIFICATION_ACCEPT_ACTION"
        }

        desktop_alert = {
            "title-loc-key": "Are you still there?",
            "loc-key": "Click to Confirm",
            "action-loc-key": "Yes"
        }

        mobile_data_message = data

        desktop_data_message = data

    except Exception as e:
        logging.getLogger().info("Exception creating push notification alerts: {}".format(e))

    return mobile_alert, desktop_alert, mobile_data_message, desktop_data_message


class NotifyAuthenticated:
    def __init__(self, app, authentication):
        self.app = app
        self.authentication = authentication

    async def send_authenticated_push_notification(self):
        device_message = {
            "data": {
                "action": "authenticated"
            }
        }
        try:
            device = json.loads(self.authentication.desktop_device)

            user_device = self.app.session.query(Device.push_notification_token, Device.device_id, Device.type,
                                                 Device.deleted_at, PushNotificationCertificate.apns_certificate_uri,
                                                 PushNotificationCertificate.use_apns_sandbox). \
                filter(Device.device_id == device['device_id']).\
                first()

            if user_device.type == DeviceType.macos:
                resp = await send_apple_push_notification(self.app,
                                                          DeviceType.macos.name,
                                                          None,
                                                          device_message,
                                                          user_device.push_notification_token,
                                                          user_device.apns_certificate_uri,
                                                          user_device.use_apns_sandbox
                                                          )

                if resp.successes:
                    logging.getLogger().info("macOS authenticated notification sent. Success response:{}"
                                             .format(resp.successes))

                if resp.errors or resp.failures:
                    if resp.errors:
                        logging.getLogger().info("macOS authenticated notification failed with errors {}"
                                                 .format(resp.errors))
                    if resp.failures:
                        logging.getLogger().info("macOS authenticated Tokens failed {}".format(resp.failures))

        except Exception as e:
            logging.getLogger().info("Failed to send authenticated notification {}".format(e))


class NotifyDevices:

    def __init__(self, app, user_id):
        self.app = app
        self.user_id = user_id

        # Initialize
        self.devices_info = {}
        self.success = 0
        self.desktop_notifications = 0
        self.mobile_notifications = 0
        self.macos_device_tokens = []
        self.macos_devices = []
        self.macos_apns_certificate_uri = None
        self.ios_apns_certificate_uri = None
        self.ios_device_tokens = []
        self.ios_devices = []
        self.android_device_tokens = []
        self.android_devices = []
        self.windows_devices = []

    def get_notification_devices(self):

        user_devices = self.app.session.query(Device.push_notification_token, Device.device_id, Device.type,
                                         Device.deleted_at, PushNotificationCertificate.apns_certificate_uri,
                                         PushNotificationCertificate.use_apns_sandbox). \
            join(UserDevice). \
            join(PushNotificationCertificate,
                 Device.push_notification_certificate_id == PushNotificationCertificate.id). \
            filter(Device.deleted_at == None). \
            filter(UserDevice.user_id == self.user_id). \
            order_by(Device.id). \
            all()

        logging.getLogger().info("got the following devices:{}".format(user_devices))

        self.app.session.flush()

        for device in user_devices:
            self.devices_info[device.device_id] = device.type.name
            if device.type == DeviceType.ios:
                self.ios_device_tokens.append(device.push_notification_token)
                self.ios_apns_certificate_uri = device.apns_certificate_uri
                self.ios_use_apns_sandbox = device.use_apns_sandbox
                self.ios_devices.append(device)

            if device.type == DeviceType.macos:
                self.macos_device_tokens.append(device.push_notification_token)
                self.macos_apns_certificate_uri = device.apns_certificate_uri
                self.macos_use_apns_sandbox = device.use_apns_sandbox
                self.macos_devices.append(device)

            if device.type == DeviceType.android:
                self.android_device_tokens.append(device.push_notification_token)
                self.android_devices.append(device)

            if device.type == DeviceType.windows:
                self.windows_devices.append(device)


    def get_session_notification_devices(self):

        user_devices = self.app.session.query(Device.push_notification_token, Device.device_id, Device.type,
                                         Device.deleted_at, PushNotificationCertificate.apns_certificate_uri,
                                         PushNotificationCertificate.use_apns_sandbox). \
            join(UserDevice). \
            join(PushNotificationCertificate,
                 Device.push_notification_certificate_id == PushNotificationCertificate.id). \
            filter(Device.deleted_at == None). \
            filter(UserDevice.user_id == self.user_id). \
            order_by(Device.id). \
            all()

        logging.getLogger().info("got the following devices:{}".format(user_devices))

        self.app.session.flush()

        for device in user_devices:
            self.devices_info[device.device_id] = device.type.name
            if device.type == DeviceType.ios:
                self.ios_device_tokens.append(device.push_notification_token)
                self.ios_apns_certificate_uri = device.apns_certificate_uri
                self.ios_use_apns_sandbox = device.use_apns_sandbox
                self.ios_devices.append(device)

            if device.type == DeviceType.macos:
                self.macos_device_tokens.append(device.push_notification_token)
                self.macos_apns_certificate_uri = device.apns_certificate_uri
                self.macos_use_apns_sandbox = device.use_apns_sandbox
                self.macos_devices.append(device)

            if device.type == DeviceType.android:
                self.android_device_tokens.append(device.push_notification_token)
                self.android_devices.append(device)

            if device.type == DeviceType.windows:
                self.windows_devices.append(device)



    async def send_session_push_notification(self, app, data):

        logging.getLogger().info("Sending push notification")

        # Initializing
        username = data['data'].get('username')
        notify_devices = self
        notify_devices.get_session_notification_devices()

        mobile_alert, desktop_alert, mobile_data_message, desktop_data_message = create_session_messages(data)

        try:
            logging.getLogger().info("Getting device data")
            logging.getLogger().info("Using requested_data {}".format(data))
            logging.getLogger().info("Mobile session notification payload = {}".format(json.dumps(mobile_data_message)))
            logging.getLogger().info("BLE Desktop session notification payload = {}".format(json.dumps(desktop_data_message)))

            # Send iOS notification
            if len(notify_devices.ios_devices) > 0:
                data_message = mobile_data_message

                if len(notify_devices.ios_devices) == 1:
                    device = notify_devices.ios_devices[0]
                    resp = await send_apple_push_notification(
                        app,
                        DeviceType.ios.name,
                        None,
                        data_message,
                        device.push_notification_token,
                        device.apns_certificate_uri,
                        device.use_apns_sandbox,
                        True
                    )

                    if resp.successes:
                        logging.getLogger().info("iOS notification sent. Success response:{}"
                                                 .format(resp.successes))
                        notify_devices.success += 1
                        notify_devices.mobile_notifications += 1

                    if resp.errors or resp.failures:
                        if resp.errors:
                            logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                     .format(resp.errors))
                        if resp.failures:
                            logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))

                else:
                    resp = await send_multiple_apple_push_notification(
                        app,
                        DeviceType.ios.name,
                        None,
                        data_message,
                        notify_devices.ios_device_tokens,
                        notify_devices.ios_apns_certificate_uri,
                        notify_devices.ios_use_apns_sandbox,
                        True
                    )

                    if resp.successes:
                        logging.getLogger().info("iOS notification sent. Success response:{}"
                                                 .format(resp.successes))
                        notify_devices.success += len(notify_devices.ios_device_tokens)
                        notify_devices.mobile_notifications += len(notify_devices.ios_device_tokens)

                    if resp.errors or resp.failures:
                        if resp.errors:
                            logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                     .format(resp.errors))
                        if resp.failures:
                            logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))

            # Send macOS notification
            if len(notify_devices.macos_devices) > 0:
                data_message = desktop_data_message

                if data_message:
                    if len(notify_devices.macos_devices) == 1:
                        device = notify_devices.macos_devices[0]
                        resp = await send_apple_push_notification(
                            app,
                            DeviceType.ios.name,
                            None,
                            data_message,
                            device.push_notification_token,
                            device.apns_certificate_uri,
                            device.use_apns_sandbox
                        )

                        if resp.successes:
                            logging.getLogger().info("iOS notification sent. Success response:{}"
                                                     .format(resp.successes))
                            notify_devices.success += 1
                            notify_devices.desktop_notifications += 1

                        if resp.errors or resp.failures:

                            if resp.errors:
                                logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                         .format(resp.errors))

                            if resp.failures:
                                logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))

                    else:
                        resp = await send_multiple_apple_push_notification(
                            app,
                            DeviceType.macos.name,
                            None,
                            data_message,
                            notify_devices.macos_device_tokens,
                            notify_devices.macos_apns_certificate_uri,
                            notify_devices.macos_use_apns_sandbox
                        )

                        if resp.successes:
                            logging.getLogger().info("macOS notification sent. Success response:{}"
                                                     .format(resp.successes))
                            notify_devices.success += len(notify_devices.macos_device_tokens)
                            notify_devices.desktop_notifications += len(notify_devices.macos_device_tokens)

                        if resp.errors or resp.failures:

                            if resp.errors:
                                logging.getLogger().info("Some macOS notifications failed with errors {}"
                                                         .format(resp.errors))

                            if resp.failures:
                                logging.getLogger().info("The following nacIS Tokens failed {}".format(resp.failures))

            # Send android notification
            if len(notify_devices.android_devices) > 0:
                message = "Session Monitor"
                data_message = mobile_data_message
                fcm_key = app.hububconfig.get("FCM_KEY")

                device = notify_devices.android_devices[0]
                resp = await send_android_push_notification(app, str(device.type.name), message,
                                                            data_message,
                                                            notify_devices.android_device_tokens,
                                                            fcm_key)

                if resp['success']:
                    logging.getLogger().info("iOS notification sent. Success response:{}"
                                             .format(resp))
                    notify_devices.success += 1
                    notify_devices.mobile_notifications += 1

                if resp['failure']:
                    logging.getLogger().info("The following iOS Tokens failed {}".format(resp))

            # Send windows notification
            if len(notify_devices.windows_devices) > 0:
                data_message = desktop_data_message
                for device in notify_devices.windows_devices:
                    result = await send_windows_push_notification(app, data_message,
                                                                  device.push_notification_token, username, "Are you still there?", "Yes")
                    if result:
                        logging.getLogger().info("Message successfully sent to windows device with device_id={}".
                                                 format(device.device_id))
                        notify_devices.success += 1
                        notify_devices.desktop_notifications += 1

                    else:
                        logging.getLogger().info(
                            "There was a problem sending a notification to windows device with device_id={}". \
                                format(device.device_id))

            if notify_devices.success == 0:
                return None, None, None

            logging.getLogger().info("There were {} successful notifications sent".
                                     format(str(notify_devices.success)))

        except Exception as e:
            logging.getLogger().info("Alchemy Exception: {}".format(e))
            app.session.rollback()

        return True, notify_devices.mobile_notifications, notify_devices.desktop_notifications


    async def send_push_notification(self, app, action, auth_request_id, data, requested_data, authentication,
                                     validation=None, communication=None, **identification_data_secret):

        logging.getLogger().info("Sending push notification")

        # Initializing
        username = data.get('username')
        notify_devices = self
        notify_devices.get_notification_devices()

        # check for action being False and force it to go to identify
        if not action:
            action = "identify"
            mobile_alert, desktop_alert, mobile_data_message, desktop_data_message = create_data_messages(auth_request_id, data, action,
                                                                                    validation,
                                                                                    identification_data_secret,
                                                                                    requested_data)
        try:
            logging.getLogger().info("Getting device data")
            logging.getLogger().info("Using requested_data {}".format(requested_data))
            logging.getLogger().info("Mobile notification payload = {}".format(json.dumps(mobile_data_message)))

            if communication['method'] == "bluetooth":
                logging.getLogger().info("BLE Desktop notification payload = {}".format(json.dumps(desktop_data_message)))

            # Send iOS notification
            if len(notify_devices.ios_devices) > 0:
                data_message = mobile_data_message

                if len(notify_devices.ios_devices) == 1:
                    device = notify_devices.ios_devices[0]
                    resp = await send_apple_push_notification(
                        app,
                        DeviceType.ios.name,
                        mobile_alert,
                        data_message,
                        device.push_notification_token,
                        device.apns_certificate_uri,
                        device.use_apns_sandbox
                    )

                    if resp.successes:
                        logging.getLogger().info("iOS notification sent. Success response:{}"
                                                 .format(resp.successes))
                        notify_devices.success += 1
                        notify_devices.mobile_notifications += 1

                    if resp.errors or resp.failures:
                        if resp.errors:
                            logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                     .format(resp.errors))
                        if resp.failures:
                            logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))
                else:
                    resp = await send_multiple_apple_push_notification(
                        app,
                        DeviceType.ios.name,
                        mobile_alert,
                        data_message,
                        notify_devices.ios_device_tokens,
                        notify_devices.ios_apns_certificate_uri,
                        notify_devices.ios_use_apns_sandbox
                    )

                    if resp.successes:
                        logging.getLogger().info("iOS notification sent. Success response:{}"
                                                 .format(resp.successes))
                        notify_devices.success += len(notify_devices.ios_device_tokens)
                        notify_devices.mobile_notifications += len(notify_devices.ios_device_tokens)

                    if resp.errors or resp.failures:
                        if resp.errors:
                            logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                     .format(resp.errors))
                        if resp.failures:
                            logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))

            # Send android notification
            if len(notify_devices.android_devices) > 0:
                message = "Verified Presence Request"
                data_message = mobile_data_message
                fcm_key = app.hububconfig.get("FCM_KEY")

                device = notify_devices.android_devices[0]
                resp = await send_android_push_notification(app, str(device.type.name), message,
                                                            data_message,
                                                            notify_devices.android_device_tokens,
                                                            fcm_key)

                if resp['success']:
                    logging.getLogger().info("iOS notification sent. Success count:{}"
                                             .format(resp['success']))
                    notify_devices.success += 1
                    notify_devices.mobile_notifications += 1
                if resp['failure']:
                    logging.getLogger().info(
                        "The following android Tokens failed count = {}".format(resp['failure']))

            # wait one second before notifying desktop devices
            sleep(1)

            # Send macOS notification
            if len(notify_devices.macos_devices) > 0:
                if communication['method'] == "bluetooth":
                    data_message = desktop_data_message

                else:
                    # We do not want to send a notification unless we are using bluetooth
                    data_message = None
                if data_message:
                    if len(notify_devices.macos_devices) == 1:
                        device = notify_devices.macos_devices[0]
                        resp = await send_apple_push_notification(
                            app,
                            DeviceType.ios.name,
                            desktop_alert,
                            data_message,
                            device.push_notification_token,
                            device.apns_certificate_uri,
                            device.use_apns_sandbox
                        )

                        if resp.successes:
                            logging.getLogger().info("iOS notification sent. Success response:{}"
                                                     .format(resp.successes))
                            notify_devices.success += 1
                            notify_devices.desktop_notifications += 1

                        if resp.errors or resp.failures:

                            if resp.errors:
                                logging.getLogger().info("Some iOS notifications failed with errors {}"
                                                         .format(resp.errors))

                            if resp.failures:
                                logging.getLogger().info("The following iOS Tokens failed {}".format(resp.failures))

                    else:
                        resp = await send_multiple_apple_push_notification(
                            app,
                            DeviceType.macos.name,
                            desktop_alert,
                            data_message,
                            notify_devices.macos_device_tokens,
                            notify_devices.macos_apns_certificate_uri,
                            notify_devices.macos_use_apns_sandbox
                        )

                        if resp.successes:
                            logging.getLogger().info("macOS notification sent. Success response:{}"
                                                     .format(resp.successes))
                            notify_devices.success += len(notify_devices.macos_device_tokens)
                            notify_devices.desktop_notifications += len(notify_devices.macos_device_tokens)

                        if resp.errors or resp.failures:

                            if resp.errors:
                                logging.getLogger().info("Some macOS notifications failed with errors {}"
                                                         .format(resp.errors))

                            if resp.failures:
                                logging.getLogger().info("The following nacIS Tokens failed {}".format(resp.failures))

            # Send windows notification
            if len(notify_devices.windows_devices) > 0:
                data_message = desktop_data_message
                for device in notify_devices.windows_devices:
                    result = await send_windows_push_notification(app, data_message,
                                                                  device.push_notification_token, username,
                                                                  "Please Verify Presence", "Accept")
                    if result:
                        logging.getLogger().info("Message successfully sent to windows device with device_id={}".
                                                 format(device.device_id))
                        notify_devices.success += 1
                        notify_devices.desktop_notifications += 1

                    else:
                        logging.getLogger().info(
                            "There was a problem sending a notification to windows device with device_id={}". \
                                format(device.device_id))

            if notify_devices.success == 0:
                return None, None, None

            logging.getLogger().info("There were {} successful notifications sent".
                                     format(str(notify_devices.success)))

            try:
                if authentication:
                    notified_devices = { 'notified' : notify_devices.devices_info, 'notified_at': format(datetime.utcnow())}
                    authentication.devices = json.dumps(notified_devices)
                    authentication.authentication_status = AuthenticationStatus.notification_sent.name
                    authentication.updated_at = datetime.utcnow()
                    authentication.save()
                    app.session.commit()
                    app.session.flush()

            except Exception as e:
                logging.getLogger().warn("SQL: Error Writing to Authentication record: {}".format(e))
                app.session.rollback()

        except Exception as e:
            logging.getLogger().info("COMMON: Error: {}".format(e))
            app.session.rollback()

        return True, notify_devices.mobile_notifications, notify_devices.desktop_notifications