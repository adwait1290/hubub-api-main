import asyncio
import logging
import os

import uvloop
import configparser

from sanic import Blueprint
from sanic import Sanic


from hubub_common.models import db

from hubub_common.util import from_pyfile

from hubub_common.models import init_listeners

from service.routes import setup_routes, setup_routes2

from hubub_common.middlewares import setup_middleware


if 'APP_LOGGER' in os.environ:
    app_logger = int(os.environ['APP_LOGGER'])
else:
    app_logger = logging.INFO

if 'APP_CONFIG_FILE' in os.environ:
    config_file = os.environ['APP_CONFIG_FILE']
    directory = os.path.dirname(os.path.abspath(__file__))
    hububconfig = from_pyfile(os.path.join(directory, 'config/%s' % config_file))
    environment, ext = os.path.splitext(config_file)
else:
    directory = os.path.dirname(os.path.abspath(__file__))
    hububconfig = from_pyfile(os.path.join(directory, './config/local.py'))
    environment = 'local'

if 'PORT' in os.environ:
    port = os.environ['PORT']
else:
    port = hububconfig.get('RUN_SERVICE_ON_PORT')

loop = uvloop.new_event_loop()
asyncio.set_event_loop(loop)

config = configparser.ConfigParser()
config.read('.bumpversion.cfg')
version = config._sections['bumpversion']['current_version']

engine, session = loop.run_until_complete(db.init_pg(hububconfig=hububconfig, version=version, recreate_schema=hububconfig.get('RECREATE_SCHEMA')))

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
    level=app_logger,datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger().setLevel(level=app_logger)

service = Sanic(hububconfig.get('SERVICE_NAME'))
print ('Kicking off: ' + service.name)
service.logger = logging.getLogger()
service.version = version
service.environment = environment

service.hububconfig = hububconfig

service.engine = engine
service.session = session
# service.devops_engine = devops_engine
# service.devops_session = devops_session

service.pgloop = loop

hububVersion1 = Blueprint('ver1', url_prefix='/api/v1')
hububVersion2 = Blueprint('apple', url_prefix='/')

init_listeners(service)

setup_routes(hububVersion1)
setup_routes2(hububVersion2)

service.blueprint(hububVersion1)
service.blueprint(hububVersion2)

setup_middleware(service)


if __name__ == '__main__':
    #start the app
    service.run(debug=hububconfig.get('DEBUG_SERVICE'),host=hububconfig.get('DEBUG_HOST'),port=port)