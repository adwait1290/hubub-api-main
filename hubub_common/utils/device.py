
import logging
import os
import re

from ..models import Device, DeviceType, UserDevice, DeviceSchema, UserDeviceSchema, RegistrationStatus, User, UserRegistrationStatus
from ..util import generate_random_chars
from ..exceptions import InvalidValueException
from sqlalchemy.orm import load_only, Load


def create_new_device(app, user):
    device_schema = DeviceSchema()
    user_device_schema = UserDeviceSchema()
    device_data = {
        'device_id': generate_random_chars(16),
        'secret': generate_random_chars(16),
        'type': DeviceType.unknown.value
    }
    device = Device()
    user_device = UserDevice()
    device, errors = device_schema.load(device_data)

    if errors:
        app.session.rollback()
        return False
    else:
        try:
            app.session.add(device)
            app.session.commit()
            logging.getLogger().info("Saved device {}".format(device))

            user_device_data = {
                'device_id': device.id,
                'user_id': user.id
            }
            user_device, errors = user_device_schema.load(user_device_data)
            app.session.add(user_device)
            app.session.commit()
            logging.getLogger().info("Saved UserDevice {}".format(user_device))

        except Exception as e:
            logging.getLogger().info("Exception saving service provider{}".format(e))
            app.session.rollback()


def create_device_on_registration(app, user):
    device_schema = DeviceSchema()
    user_device_schema = UserDeviceSchema()
    device = app.session.query(Device). \
        options(
            Load(Device).load_only("id","secret","registration_status","deleted_at")
        ). \
        filter(Device.deleted_at == None). \
        join(UserDevice).\
        filter(UserDevice.user_id == user.id).\
        one_or_none()
    if device:
        logging.getLogger().warn("User already has a registered device.")
    else:
        device_data = {
            'device_id': generate_random_chars(16),
            'secret': generate_random_chars(16),
            'type': DeviceType.unknown.value
        }
        device = Device()
        user_device = UserDevice()
        device, errors = device_schema.load(device_data)

        if errors:
            app.session.rollback()
            return False
        else:
            try:
                app.session.add(device)
                app.session.commit()
                logging.getLogger().info("Saved device {}".format(device))

                user_device_data = {
                    'device_id': device.id,
                    'user_id': user.id
                }
                user_device, errors = user_device_schema.load(user_device_data)
                app.session.add(user_device)
                app.session.commit()
                logging.getLogger().info("Saved UserDevice {}".format(user_device))

            except Exception as e:
                logging.getLogger().info("Exception saving service provider{}".format(e))
                app.session.rollback()

        return device


def create_desktop_device(app, user, data):
    device_schema = DeviceSchema()
    user_device_schema = UserDeviceSchema()
    device_type = data['push_notification_class']
    try:
        config_environment = os.environ['APP_CONFIG_FILE']
    except Exception:
        config_environment = "local.py"

    environment = re.sub(r'\.py', '', config_environment)
    logging.getLogger().info("Environment {}".format(environment))

    if environment in ["dev", "local"]:
        if device_type == DeviceType.macos.value:
            push_notification_certificate_id = 6
        elif device_type == DeviceType.windows.value:
            push_notification_certificate_id = 8
    elif environment in ["prod", "stage"]:
        if device_type == DeviceType.macos.value:
            push_notification_certificate_id = 5
        elif device_type == DeviceType.windows.value:
            push_notification_certificate_id = 7

    logging.getLogger().info("push_notification_certificate_id {}".format(push_notification_certificate_id))

    device_data = {
        'device_id': generate_random_chars(16),
        'secret': generate_random_chars(16),
        'push_notification_token': data['notification_token'],
        'type': device_type,
        'push_notification_certificate_id': push_notification_certificate_id
    }
    device = Device()
    user_device = UserDevice()
    device, errors = device_schema.load(device_data)
    device.registration_status = RegistrationStatus.completed.name

    if errors:
        app.session.rollback()
        return False
    else:
        try:
            app.session.add(device)
            app.session.commit()
            logging.getLogger().info("Saved device {}".format(device))
            app.session.flush()

            user_device_data = {
                'device_id': device.id,
                'user_id': user.id
            }
            user_device, errors = user_device_schema.load(user_device_data)
            user.user_registration_status = UserRegistrationStatus.started.name
            app.session.add(user_device)
            app.session.commit()
            logging.getLogger().info("Saved UserDevice {}".format(user_device))
            app.session.flush()
        except Exception as e:
            logging.getLogger().info("Exception saving service provider{}".format(e))
            app.session.rollback()
    return device


def update_device_registration_status(request, device_id, registration_status):
    try:
        device_id = str(device_id)
        device = request.app.session.query(Device). \
            options(
                Load(Device).load_only("id","registration_status","deleted_at")
            ). \
            filter(Device.deleted_at == None).\
            filter(Device.device_id == device_id). \
            one_or_none()
        if not device:
            logging.getLogger().warn("Device with given device_id={} doesn't exist"
                                    .format(device_id))
            raise InvalidValueException("device_id")

        device.registration_status = registration_status
        device.save()
        request.app.session.commit()
        request.app.session.flush()
        return True
    except Exception as e:
        logging.getLogger().info("Exception updating device information: {}".format(e))
        request.app.session.rollback()
        return False


async def get_device_by_id(request, device_id):
    """ Tries to get IdentificationDataDevice by given device_id.

    :param app: application entity
    :param device_id: device ID
    :raise 404: if device with given device_id is not found
    :return: lookup IdentificationDataDevice entity
    """
    device_id = str(device_id)
    try:
        device = request.app.session.query(Device). \
            options(
                Load(Device).load_only("id", "device_id", "registration_status", "push_notification_token",
                                       "type", "deleted_at")
            ). \
            filter(Device.deleted_at == None). \
            filter(Device.device_id == device_id).\
            order_by(Device.id). \
            one_or_none()

        if device:
            logging.getLogger().warn("Device with given device_id={} found"
                                    .format(device_id))
            return device
        else:
            logging.getLogger().warn("Device with given device_id={} doesn't exist"
                                    .format(device_id))
            raise InvalidValueException("device_id")
    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        request.app.session.rollback()
        return None


async def get_user_id_by_device_id(request, device_id):

    try:
        user_device = request.app.session.query(UserDevice).\
            filter(UserDevice.device_id == device_id).\
            one_or_none()
        if user_device:
            return user_device.user_id
        logging.getLogger().warn("User with device_id={} was not found".format(device_id))
        return None
    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        request.app.session.rollback()
        return None


async def get_user_by_device_id(request, device_id):
    try:
        device = request.app.session.query(Device).filter(Device.device_id == device_id).\
            filter(Device.deleted_at == None).one_or_none()
    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        request.app.session.rollback()
        return None
    user_id = await get_user_id_by_device_id(request, device.id)
    try:
        user = request.app.session.query(User).\
            filter(User.deleted_at == None). \
            filter(User.id == user_id).\
            one_or_none()
        if user:
            return user
        logging.getLogger().warn("User with device_id={} was not found".format(device_id))
        return None
    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        request.app.session.rollback()
        return None