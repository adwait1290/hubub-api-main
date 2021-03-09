
from ._types import *

# contact orm
from .contact_email import *
from .email import *
from .contact import *

# push_notification
from .push_notification_certificate import *

# Hubs
from .image import *
from .detailed_hub import *
from .simple_hub import *
from .user_simplehub import *
from .user_detailedhub import *

# user orm
from .service_provider import *
from .user_tag import *
from .user import *
from .device import *
# account orm

# authentication transaction orm
from .authentication import *

# api token orm
from .token import *

# backend pki
from .keys import *

from .client_application import *


# from hubub_common.devops.control import record_devops_data


def init_listeners(service):

    @service.listener('after_server_start')
    async def notify_server_started(service, loop):
        # record_devops_data(service)
        pass

    @service.listener('before_server_stop')
    async def notify_server_stopping(service, loop):
        print('Server shutting down!')
        service.session.rollback()

    @service.listener('after_server_stop')
    async def close_db(service, loop):
        print('Server down! Closing database session.')
        service.session.close()