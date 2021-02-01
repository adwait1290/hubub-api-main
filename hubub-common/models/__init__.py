
from ._types import *

# contact orm
from .contact_email import *
from .contact_postal_address import *
from .contact_telephone import *
from .email import *
from .postal_address import *
from .telephone import *
from .contact import *

# push_notification
from .push_notification_certificate import *

# user orm
from .group import *
from .service_provider import *
from .user_group_service_provider import *
from .user_tag import *
from .user_facial_model import *
from .user_device import *
from .user import *
from .device import *
from .facial_model import *

# account orm
from .account_group import *
from .account_tag import *
from .account import *

# authentication transaction orm
from .authentication import *

# api token orm
from .token import *

# backend pki
from .keys import *

from .client_application import *
from .authorization_token import *


from hubub_common.devops.control import record_devops_data


def init_listeners(service):

    @service.listener('after_server_start')
    async def notify_server_started(service, loop):
        record_devops_data(service)

    @service.listener('before_server_stop')
    async def notify_server_stopping(service, loop):
        print('Server shutting down!')
        service.session.rollback()

    @service.listener('after_server_stop')
    async def close_db(service, loop):
        print('Server down! Closing database session.')
        service.session.close()