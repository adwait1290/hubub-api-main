import logging
import urllib
from sanic.response import json as sanic_response_json

from hubub_common.exceptions import (
    PermissionDenied,
    InvalidValueException
)

from hubub_common.models import (
    Account,
    User,
    ServiceProvider,
    UserGroupServiceProvider
)


def get_service_provider(app, authentication_url):
    try:
        service_provider = app.session.query(ServiceProvider).filter(
            ServiceProvider.authentication_url == authentication_url).one_or_none()

        if not service_provider:
            logging.getLogger().warn("ServiceProvider with given authentication_url={} doesn't exist"
                                    .format(authentication_url))
            raise InvalidValueException('authentication_url')

        user_group_service_provider = app.session.query(UserGroupServiceProvider).filter(
            UserGroupServiceProvider.service_provider_id == service_provider.id).first()

        user = app.session.query(User). \
            filter(User.id == user_group_service_provider.user_id). \
            one_or_none()

        account = app.session.query(Account).filter(Account.id == user.account_id).one_or_none()
        app.session.flush()

    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        app.session.rollback()

    return sanic_response_json({
        "id_provider": {
            "account_id": account.id,
            "account_name": account.name,
            "authentication_url": authentication_url,
            "logo_url": service_provider.logo_url,
            "client_name": user.idtoken,
            "client_secret": user.secret1,
            "username": urllib.parse.quote(user.username)
        }
    })