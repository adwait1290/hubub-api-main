
from datetime import datetime
import json
import logging
import os
import re
import requests

from ua_parser import user_agent_parser
from user_agents import parse as user_agents_details_parser

from ..models import Authentication, AuthenticationSchema, AuthenticationMethod, AuthenticationStatus
from ..exceptions import InvalidValueException
from sqlalchemy.orm import load_only, Load


async def get_authentication_ping_by_user_id(request, user_id):
    user_id = str(user_id)
    try:
        authentication = request.app.session.query(Authentication). \
            options(
                Load(Authentication).load_only("id")
            ). \
            filter(Authentication.user_id == user_id). \
            filter(Authentication.authentication_result == None). \
            order_by(Authentication.updated_at). \
            one_or_none()

        if authentication:
            logging.getLogger().warn("Authentication for user_id={} found"
                                    .format(user_id))
            return authentication
        else:
            logging.getLogger().warn("Authentication for user_id={} not found"
                                    .format(user_id))
            raise InvalidValueException("user_id")
    except Exception as e:
        logging.getLogger().info("Alchemy Exception: {}".format(e))
        request.app.session.rollback()


async def record_geolocation(request, authentication):
    # Get Geolocation Information
    url = ''.join([
        request.app.hububconfig.get('GEO_SERVICE_BASE_URL'),
        "/json/",
        request.remote_addr
    ])

    attempts = 0
    while attempts < 3:
        try:
            geolocation = requests.get(url=url, headers={
                'Connection': 'close'})  # Response Format: '{"ip":"127.0.0.1","country_code":"","country_name":"","region_code":"","region_name":"","city":"","zip_code":"","time_zone":"","latitude":0,"longitude":0,"metro_code":0}'

            if geolocation:
                logging.getLogger().info(
                    "GOT THE FOLLOWING GEOLOCATION DATA FROM REQUEST TO hubub_GEO : {}".format(geolocation))
                break
            continue

        except requests.HTTPError as exc:
            geolocation = None
            attempts += 1
            logging.getLogger().warn("ERROR GETTING GEOLOCATION DATA = {}".format(exc))

        except requests.ConnectionError as exc:
            geolocation = None
            attempts += 1
            logging.getLogger().warn("ERROR GETTING GEOLOCATION DATA = {}".format(exc))

    if not geolocation:
        logging.getLogger().warn("Could not get geolocation data")
        geolocation = {}
        geolocation = '{"ip":"","country_code":"","country_name":"","region_code":"","region_name":"","city":"","zip_code":"","time_zone":"","latitude":0,"longitude":0,"metro_code":0}'

    try:
        authentication.geolocation = str(geolocation.content, 'utf-8')
        authentication.updated_at = datetime.utcnow()
        authentication.save()
        request.app.session.commit()
        logging.getLogger().info("Recorded Geolocation {}".format(authentication))
        request.app.session.flush()
        return authentication

    except Exception as e:
        logging.getLogger().info("Exception saving Geolocation{}".format(e))
        request.app.session.rollback()
        return None


def save_authentication(request, auth_request_id, authentication_method, user_agent, user_id, push_notification_certificate_id):
    authentication = Authentication()
    authentication_schema = AuthenticationSchema()

    user_agent_info = user_agent_parser.Parse(user_agent)
    user_agent_details = user_agents_details_parser(user_agent)

    authentication_json = {
        'user_id': user_id
        , 'push_notification_certificate_id': push_notification_certificate_id
        , 'browser_device': json.dumps(user_agent_info['device'])
        , 'browser': json.dumps(user_agent_info['user_agent'])
        , 'os': json.dumps(user_agent_info['os'])
        , 'useragent': json.dumps({
            'is_mobile': user_agent_details.is_mobile,
            'is_tablet': user_agent_details.is_tablet,
            'is_touch_capable': user_agent_details.is_touch_capable,
            'is_pc': user_agent_details.is_pc,
            'is_bot': user_agent_details.is_bot
        })
        , 'ipaddress': request.remote_addr
        , 'port': request.ip[1]
        , 'geolocation': ''
        , 'auth_request_id': auth_request_id
    }
    authentication, errors = authentication_schema.load(authentication_json)
    if errors:
        logging.getLogger().warn("Error loading the data {}".format(errors))

    if authentication_method == 'manual':
        authentication_method = AuthenticationMethod.manual.name

    elif authentication_method == 'bluetooth':
        authentication_method = AuthenticationMethod.bluetooth.name

    elif authentication_method == 'geolocation':
        authentication_method = AuthenticationMethod.geolocation.name

    elif authentication_method == 'sonic':
        authentication_method = AuthenticationMethod.sonic.name

    elif authentication_method == 'facial':
        authentication_method = AuthenticationMethod.facial.name

    elif authentication_method == "validation_server":
        authentication_method = AuthenticationMethod.validation_server.name

    try:
        authentication.authentication_status = AuthenticationStatus.started.name
        authentication.authentication_method = authentication_method
        authentication.updated_at = datetime.utcnow()
        request.app.session.add(authentication)
        request.app.session.commit()
        logging.getLogger().info("Authentication Method of {0} set for Auth_Request_ID = {1}"
                                .format(authentication_method, auth_request_id))
        logging.getLogger().info("Saved authentication{}".format(authentication))
        request.app.session.flush()
        return authentication

    except Exception as e:
        logging.getLogger().info("Exception saving authentication{}".format(e))
        request.app.session.rollback()
        return None