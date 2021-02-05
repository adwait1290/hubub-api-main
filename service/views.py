# -*- coding: utf-8 -*-
import logging
import os.path
import re
import threading
import urllib
import time
import requests


requests.packages.urllib3.disable_warnings()

from sqlalchemy.orm import load_only, Load
from sqlalchemy import or_, desc, any_, update, and_
from sqlalchemy.sql.expression import bindparam, and_
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import quote

from datetime import datetime, timedelta

from sanic.response import json as sanic_response_json, HTTPResponse
from sanic.response import html
from sanic.views import HTTPMethodView

from .util import *

from hubub_common.redis import *

from hubub_common.exceptions import (
    InvalidCredentialsException,
    BaseAuthenticationException,
)

from hubub_common.models import (
    User,
    Authentication,
    AuthenticationSchema,
    AuthenticationStatus,
    AuthenticationResult,
    AuthenticationLoginSchema,
    Device,
    UserDevice,
    DeviceType,
    RegistrationStatus,
    AuthenticationSessionStatus,
    AuthenticationMethod
)

from hubub_common.util import (
    generate_secret_key,
    make_authentication_headers,
    verify_authentication_headers,
)

from hubub_common.utils.authentication import get_authentication_ping_by_user_id, save_authentication, record_geolocation

from hubub_common.exceptions import (
    handle_response_on_error,
    BaseHTTPException
)

from hubub_common.s3access import *


AUTH_STATUS_SUCCESS = "authentication_success"
AUTH_STATUS_FAILED = "authentication_failed"


class ApiVersionView(HTTPMethodView):
    def get(self, request):
        ver = sanic_response_json({'version': request.app.version, 'process': str(os.getpid())})
        return ver


class RegisterView(HTTPMethodView):

    async def post(self, request):

        return sanic_response_json({"device": {
            "status": "Dummy User Created Response",
        }
        }, status=200)


class LoginView(HTTPMethodView):

    async def post(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)

        return sanic_response_json({"device": {
            "status": "Dummy User Login Response",
        }
        }, status=200)


class HomeView(HTTPMethodView):

    async def get(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        username = data['username']
        user = request.app.session.query(User). \
            filter(User.username == username). \
            filter(User.deleted_at == None).one_or_none()
        # User Found
        if user:
            pass
        # No User Found
        else:
            pass

        return sanic_response_json(
            {"hubs": {
                "detailed_hubs": [
                    {"title": "",
                     "description": "",
                     "is_published": "",
                     "hub_url": "",
                     "image_url": "",
                     "order": ""
                     }, {}
                ],
                "simple_hubs": [
                    {
                        "title": "",
                        "url_type": "",
                        "is_published": "",
                        "hub_url": "",
                        "image_url": "",
                        "order": ""
                    }, {}
                ]
            }
        }, status=200)


class CreateDetailedHubView(HTTPMethodView):
    async def post(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        username = data['username']
        user = request.app.session.query(User). \
            filter(User.username == username). \
            filter(User.deleted_at == None).one_or_none()
        # User Found
        if user:
            pass
        # No User Found
        else:
            pass

        return sanic_response_json({
            "title": "",
            "description": "",
            "is_published": "",
            "hub_url": "",
            "image_url": "",
            "order": ""
        }, status=200)


class EditDetailedHubView(HTTPMethodView):

    async def post(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        username = data['username']
        user = request.app.session.query(User). \
            filter(User.username == username). \
            filter(User.deleted_at == None).one_or_none()
        # User Found
        if user:
            pass
        # No User Found
        else:
            pass

        return sanic_response_json({
            "title": "",
            "description": "",
            "is_published": "",
            "hub_url": "",
            "image_url": "",
            "order": ""
        }, status=200)


class CreateSimpleHubView(HTTPMethodView):

    async def post(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        username = data['username']
        user = request.app.session.query(User). \
            filter(User.username == username). \
            filter(User.deleted_at == None).one_or_none()
        # User Found
        if user:
            pass
        # No User Found
        else:
            pass

        return sanic_response_json({
            "title": "",
            "description": "",
            "is_published": "",
            "hub_url": "",
            "image_url": "",
            "order": ""
        }, status=200)


class EditSimpleHubView(HTTPMethodView):

    async def post(self, request):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        username = data['username']
        user = request.app.session.query(User). \
            filter(User.username == username). \
            filter(User.deleted_at == None).one_or_none()
        # User Found
        if user:
            pass
        # No User Found
        else:
            pass

        return sanic_response_json({
            "title": "",
            "description": "",
            "is_published": "",
            "hub_url": "",
            "image_url": "",
            "order": ""
        }, status=200)


class AppleAppSiteAssociationView(HTTPMethodView):

    async def get(self, request):
        current_dir = os.path.abspath(os.curdir)
        file = 'apple-app-site-association.json'
        dir = os.path.join(current_dir, 'hubub_common','apple/%s' % file)

        logging.getLogger().info("Loading apple app site association file {}".dir)

        try:
            with open(dir) as file_:
                json_data = json.load(file_)
                return sanic_response_json(json_data)
        except FileNotFoundError:
            return sanic_response_json({'status': 'Failed'}, status=400)


class AuthenticationLoginView(HTTPMethodView):
    def worker(self, request, authentication):
        try:
            authentication.authentication_session_status = AuthenticationSessionStatus.expired.name
            authentication.save()
            logging.getLogger().info("Changed auth_Request_id={}".format(authentication.auth_request_id))
        except Exception as e:
            request.app.session.rollback()

    async def post(self, request, username):

        # Get Request URL, handle dev
        request_uri = quote(str(request.url), safe=':/%')
        if request_uri.startswith('http://') and 'localhost' not in request_uri:
            logging.getLogger().warn(
                "[VERIFY AUTH HEADERS]: Got request URI with HTTP scheme ({}). Making HTTPS URI.."
                    .format(request_uri))
            request_uri = request_uri.replace('http://', 'https://')

        # Get Account and User Data
        username = urllib.parse.unquote(username)
        try:
            json_data = request.json
        except Exception as e:
            encoded_data = request.body.decode("utf-8")
            json_data = json.loads(encoded_data)
        push_notification_certificate_id = None

        # loading authentication login schema as soon as we have the json_data
        authentication_login_schema = AuthenticationLoginSchema()
        authentication_login, errors = authentication_login_schema.load(json_data)
        logging.getLogger().info("auth_login_schema loaded with:{}".format(authentication_login))

        try:
            user = request.app.session.query(User). \
                filter(User.username == username).\
                filter(User.deleted_at == None).one_or_none()
            if user:
                    # self.run_kill(request, authentication_active)
                    # for i in range(authentication_active):
                    #     t = threading.Thread(target=self.worker, args=(authentication_active[i],))
                    #     t.start()
                # try:
                #     update_result = request.app.session.query(Authentication). \
                #         filter(
                #         and_(Authentication.user_id == user.id,
                #              Authentication.authentication_session_status != "expired")). \
                #             update({"authentication_session_status": "expired"}, synchronize_session ="evaluate")
                #
                #     logging.getLogger().debug("Update result {0}".format(str(update_result)))
                #     request.app.session.commit()
                # except:
                #     logging.getLogger().error("Failed to close existing sessions")
                #     request.app.session.rollback()


                try:
                    devices = request.app.session.query(Device.type, Device.registration_status,
                                                    Device.push_notification_certificate_id, Device.deleted_at).join(UserDevice).filter(
                                                    UserDevice.user_id == user.id).\
                                                    filter(Device.deleted_at == None).all()
                except Exception as e:
                    logging.getLogger().info("Alchemy Exception: {}".format(e))
                    request.app.session.rollback()

            else:
                logging.getLogger().warn("USER WITH USERNAME={} NOT FOUND".format(username))

                return sanic_response_json({"status": False}, status=500)

            for d in devices:

                if d.type == DeviceType.android.value or DeviceType.ios.value and d.registration_status == RegistrationStatus.completed.name:
                    device = d
                    break

                else:
                    logging.getLogger().warn("Your device is either not registered or we could not find it")
                    device = None

            account_name = re.sub(r'.*@', '', username)

            if device:
                push_notification_certificate_id = device.push_notification_certificate_id

            else:
                push_notification_certificate_id = request.app.hububconfig.get("PUSH_NOTIFICATION_CERT_IOS_DEFAULT")

        except Exception as e:
            logging.getLogger().info("Alchemy Exception: {}".format(e))
            request.app.session.rollback()

        auth_request_id = generate_secret_key()

        authentication = save_authentication(
                                request=request,
                                auth_request_id=auth_request_id,
                                authentication_method=authentication_login['communication']['method'],
                                user_agent=request.headers['user-agent'],
                                user_id=user.id,
                                push_notification_certificate_id=push_notification_certificate_id
                            )

        logging.getLogger().info(
            "Authenticating user with username={0} and data {1}"
                .format(username, authentication_login['requested_data']))

        # record geolocation data
        authentication = await record_geolocation(request, authentication)

        # Validation Data
        prefix_length = request.app.hububconfig.get('VALIDATION_PREFIX_LENGTH')
        secret_length = request.json['validation']['secret_length']

        validation_data = {
            "validation_prefix": auth_request_id[:prefix_length],
            "validation_secret": generate_secret_key()[:secret_length] if secret_length else generate_secret_key(),
            "validation_data_secret": generate_secret_key()
        }

        validation_secret = validation_data.get("validation_secret")
        validation_data_secret = validation_data.get("validation_data_secret")
        validation_prefix = validation_data.get("validation_prefix")

        logging.getLogger().info("Got request with communication:{}".format(request.json['communication']))
        logging.getLogger().info("Got request with validation:{}".format(json.dumps(validation_data)))

        # send notification
        try:
            post_push_notification_response = await IdentificationService().post_push_notification(
                request,
                user_id=user.id,
                auth_request_id=auth_request_id,
                push_notification_certificate_id = push_notification_certificate_id,
                requested_data=authentication_login['requested_data'],
                validation=json.dumps(validation_data),
                communication=authentication_login['communication']
            )

        except BaseHTTPException as exc:

            raise BaseAuthenticationException(
                status_code=500,
                status='Timeout',
                description='Unable to get response from device. Request timeout'
            )

        # prepare response
        pns_response_encoding = post_push_notification_response.content.decode('utf-8')
        logging.getLogger().info("PNS RESPONSE: ******* : {}".format(pns_response_encoding))
        if pns_response_encoding:
            pns_json = json.loads(pns_response_encoding)
            desktop_notifications = pns_json['desktop_notifications']
            mobile_notifications = pns_json['mobile_notifications']
        else:
            desktop_notifications = 0
            mobile_notifications = 0
        response_body = json.dumps({
                                    "user_data": {
                                        "account_name": account_name,
                                        "username": username
                                    },
                                    "auth_request_id": auth_request_id,
                                    "validation_prefix": validation_prefix,
                                    "validation": json.dumps(request.json['validation']),
                                    "validation_data_secret": validation_data_secret,
                                    "communication": json.dumps(request.json['communication']),
                                    "desktop_notifications": desktop_notifications,
                                    "mobile_notifications": mobile_notifications
                                    })

        authentication_response = HTTPResponse()
        authentication_response.headers['X-hubub-Authentication-Timestamp'] = str(int(time.time()))
        authentication_response.headers['X-hubub-Authentication-Version'] = '1'
        authentication_response.headers['Content-Type'] = 'application/json; charset=utf-8'

        authentication_response.content_type = 'application/json; charset=utf-8'
        authentication_response.body = response_body.encode()



        return authentication_response


class AuthenticationLogoutView(HTTPMethodView):

    async def post(self, request, username):
        if (
            request.method == 'POST'
            and str(request.url).endswith('accounts')
        ):
            if not request.cookies:
                raise BaseHTTPException({
                    "error": {
                        "status": "missing_credentials",
                        "description": "Request did not include the required credentials."
                    }
                }, status_code=401)

            try:
                token = request.cookies.get('hubub_auth_tkt')
            except ValueError:
                raise BaseHTTPException({
                    "error: ": {
                        "status": "missing_credentials",
                        "description": "Request did not include the required credentials."
                    }
                }, status_code=401)

        request_uri = quote(str(request.url), safe=':/%')
        if request_uri.startswith('http://') and 'localhost' not in request_uri:
            logging.getLogger().warn(
                "[VERIFY AUTH HEADERS]: Got request URI with HTTP scheme ({}). Making HTTPS URI.."
                    .format(request_uri))
            request_uri = request_uri.replace('http://', 'https://')

        # Get Account and User Data
        username = urllib.parse.unquote(username)
        json_data = request.json

        encoding = request.body.decode("utf-8")
        kwargs = request.body
        data = json.loads(encoding)

        logging.getLogger().info(
            "Got POST request for logout with username={}"
            .format(username))


        return sanic_response_json({'status':204})


class AuthenticationStatusView(HTTPMethodView):

    # @async_validate_strict_schema(AuthenticationStatusSchema())
    async def post(self, request, auth_request_id):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)

        logging.getLogger().info(
            "Got POST request for checking authentication status with auth_request_id={} "
            "and parameters={}".format(auth_request_id, auth_request_id))

        # sending request for getting authentication status
        logging.getLogger().info(
            "Getting authentication request status for auth_request_id={} and "
            "authentication_status_secret={} using hubub client"
            .format(auth_request_id, data["authentication_status_secret"]))

        try:
            authentication_status_server_secret = await redisget(request.app, auth_request_id, RedisDatabase.Authentication)
            if not authentication_status_server_secret:
                logging.getLogger().warn("Could not find the authentication_status_secret on the Redis Database")

            authentication_status_secret = authentication_status_server_secret.decode("utf-8")
            if authentication_status_secret == data['authentication_status_secret']:
                logging.getLogger().info(
                    "Stored and received secrets for auth_request_id={} are equal."
                        .format(auth_request_id))

                authenticated, status = True, AUTH_STATUS_SUCCESS


            else:
                logging.getLogger().info(
                    "Stored and received secrets for auth_request_id={} are not equal."
                        .format(auth_request_id))
                authenticated, status = False, AUTH_STATUS_FAILED

            logging.getLogger().info("SENDING BACK DATA:{}".format(data))
            return sanic_response_json( {
                "authentication_status": {
                    "authenticated": authenticated,
                    "status": status,
                    'user_data': data
                }
            })
        except Exception as exc:
            logging.getLogger().error(
                "Got an exception during getting authentication request status: {}"
                .format(exc))


class ValidateAuthStatus(HTTPMethodView):
    async def post(self, request, auth_request_id):

        authenticated = False

        try:
            authentication = request.app.session.query(Authentication).\
                filter(Authentication.auth_request_id == auth_request_id).\
                filter(Authentication.deleted_at == None).\
                one_or_none()
            request.app.session.flush()

        except Exception as e:
            logging.getLogger().warn("Could not get authentication with auth_request_id={}".format(auth_request_id))
            return sanic_response_json({"status": "False"})

        if authentication:

            server_secret = authentication.authentication_status_secret
            auth_secret = await redisget(request.app, auth_request_id, RedisDatabase.Authentication)

            if auth_secret:

                if auth_secret.decode() == server_secret:
                    logging.getLogger().info("Secret's are matching for auth_request_id={}".format(auth_request_id))

                    logging.getLogger().info("Walkaway_data = {}".format(authentication.walkaway_data))
                    authenticated = True
                    authentication_session_status = AuthenticationSessionStatus.active.name

                    try:
                        authentication.save()
                        request.app.session.commit()
                        request.app.session.flush()
                        response = {"authentication_status": {
                                        "authenticated": authenticated,
                                        "session_status": authentication.authentication_session_status
                                            }
                                    }
                    except Exception as e:
                        logging.getLogger().warn("SQLALCHEMY ERROR {}".format(e))
                        request.app.session.rollback()


                    return sanic_response_json(response)

                else:
                    logging.getLogger().warn("Your secrets do not match for auth_request_id={}".format(auth_request_id))

                    try:
                        authentication.authentication_session_status = AuthenticationSessionStatus.inactive.name
                        authentication.save()
                        request.app.session.commit()
                        request.app.session.flush()
                        response = {"authentication_status": {
                                                    "authenticated": authenticated,
                                                    "session_status": authentication.authentication_session_status
                                                        }
                                                }
                    except Exception as e:
                        logging.getLogger().warn("SQLALCHEMY ERROR {}".format(e))
                        request.app.session.rollback()


                    return sanic_response_json(response)

            else:
                logging.getLogger().info("There is not auth_secret on the redis database with auth_request_id={}".format(auth_request_id))

                try:
                    authentication.authentication_session_status = AuthenticationSessionStatus.inactive.name
                    authentication.save()
                    request.app.session.commit()
                    request.app.session.flush()
                    response = {"authentication_status": {
                                                    "authenticated": authenticated,
                                                    "session_status": authentication.authentication_session_status
                                                        }
                                                }
                except Exception as e:
                    logging.getLogger().warn("SQLALCHEMY ERROR {}".format(e))
                    request.app.session.rollback()

                return sanic_response_json(response)


class GetAuthStatus(HTTPMethodView):
    async def post(self, request, auth_request_id):

        authenticated = False

        try:
            authentication = request.app.session.query(Authentication).\
                filter(Authentication.auth_request_id == auth_request_id).\
                filter(Authentication.deleted_at == None).\
                one_or_none()
            request.app.session.flush()

        except Exception as e:
            logging.getLogger().warn("Could not get authentication with auth_request_id={}".format(auth_request_id))
            return sanic_response_json({"status": "False"})

        if authentication:
            if authentication.authentication_result == AuthenticationResult.allowed.name:
                authenticated = True

            update_authentication = False
            current_date_time = datetime.utcnow()
            elapsed_seconds = (current_date_time - authentication.updated_at).total_seconds()

            timeout_walkaway = request.app.hububconfig.get('PROXIMITY_TIMEOUT_WALKAWAY')
            timeout_close = request.app.hububconfig.get('PROXIMITY_TIMEOUT_CLOSE')

            # Check when the record was last updated.

            # Greater that 5 minutes is considered closed.
            if elapsed_seconds > timeout_close:
                authentication.authentication_session_status = AuthenticationSessionStatus.closed.name
                update_authentication = True
            elif elapsed_seconds > timeout_walkaway:
                authentication.authentication_session_status = AuthenticationSessionStatus.walkaway.name
                update_authentication = True

            # If we have changed anything, update the database now.
            if update_authentication:
                try:
                    authentication.save()
                    request.app.session.commit()
                except SQLAlchemyError as e:
                    logging.getLogger().error("Unable to update authentication session status {}".format(e))
                    request.app.session.rollback()
                    return sanic_response_json({"status": "False"})


            response = {"authentication_status": {
                "authenticated": authenticated,
                "session_status": authentication.authentication_session_status
            }
            }

            return sanic_response_json(response)
        else:
            response = {"authentication_status": {
                "authenticated": False,
                "session_status": AuthenticationSessionStatus.expired.name
            }}
            return sanic_response_json(response)


class DestroyAuthSession(HTTPMethodView):
    async def post(self, request, auth_request_id):

        try:
            authentication = request.app.session.query(Authentication). \
                filter(Authentication.auth_request_id == auth_request_id). \
                filter(Authentication.deleted_at == None). \
                one_or_none()
            request.app.session.flush()

        except Exception as e:
            logging.getLogger().warn("Could not get authentication with auth_request_id={}".format(auth_request_id))
            return sanic_response_json({"status": "False"})

        try:
            authentication.authentication_session_status = AuthenticationSessionStatus.closed.name
            authentication.updated_at = datetime.utcnow()
            authentication.save()
            request.app.session.commit()
            request.app.session.flush()

            status = await redisdel(request.app, auth_request_id, RedisDatabase.Authentication)

            if status:
                return sanic_response_json({"status": "True"})
            else:
                logging.getLogger().warn("Could not delete the auth_request_id = {} from redis".format(auth_request_id))
                return sanic_response_json({"status": "False"})

        except Exception as e:
            logging.getLogger().warn("SQLALCHEMY ERROR {}".format(e))
            request.app.session.rollback()
            return sanic_response_json({"status": "False"})



class AuthenticationPingView(HTTPMethodView):

    # @async_validate_strict_schema(AuthenticationStatusSchema())
    async def post(self, request, user_id):

        # service_id, service_secret = get_service_credentials(request.app, "AUTHENTICATION_SERVICE")
        # verify_authentication_headers(request.app, request.headers, service_secret, request.url)

        logging.getLogger().info(
            "Got POST request for checking authentication status for user_id={} ".format(user_id))

        try:

            authentication = await get_authentication_ping_by_user_id(request, user_id)

            if authentication:
                return sanic_response_json({
                    "true"
                })
            else:
                return sanic_response_json({
                    "false"
                })
        except Exception as exc:
            logging.getLogger().error(
                "Got an exception during authentication ping: {}"
                            .format(exc))
            return sanic_response_json({
                "false"
            })


# ***********************************************
# Validation Views
# ***********************************************

class RequestValidationView(HTTPMethodView):

    async def post(self, request, auth_request_id):
        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        logging.getLogger().info(
            "Got request with auth_request_id={} and parameters={}"
            .format(auth_request_id, data))

        try:
            authentication = request.app.session.query(Authentication).filter(
                Authentication.auth_request_id == auth_request_id). \
                filter(Authentication.deleted_at == None).one_or_none()

            if not authentication:
                logging.getLogger().warn("AUTHENTICATION NOT FOUND!! COULD NOT UPDATE STATUS OF AUTH WITH AUTH_REQUEST_ID={}"
                                        .format(auth_request_id))
                return sanic_response_json({
                                    "authentication_status": {
                                                    "authenticated": False,
                                                    "session_status": "",
                                                    "authentication_status_secret": "",
                                                        }
                                                })
            authentication.authentication_status = AuthenticationStatus.validation_requested.name
            authentication.updated_at = datetime.utcnow()
            authentication.save()
            request.app.session.commit()
            request.app.session.flush()

        except Exception as e:
            logging.getLogger().info("Exception saving authentication{}".format(e))
            request.app.session.rollback()

        escaped_validation_data, status = await get_validation_data(request, auth_request_id)
        validation_data = escaped_validation_data.strip()

        if status != 200:

            return sanic_response_json(validation_data, status=status)

        validation = json.loads(validation_data)
        logging.getLogger().info("VALIDATION_DATA_SECRET ={}".format(validation['validation_data_secret']))
        verify_authentication_headers(request.app, request.headers,
                                      validation['validation_data_secret'],
                                      request.url)

        validation_status = await get_validation_status(
            request, auth_request_id, data['validation_secret']
        )
        if not validation_status:
            try:
                authentication.authentication_result = AuthenticationResult.failed.name
                authentication.authentication_status = AuthenticationStatus.completed.name
                authentication.authentication_session_status = AuthenticationSessionStatus.inactive.name
                authentication.updated_at = datetime.utcnow()
                authentication.logged_in_at = datetime.utcnow()
                authentication.save()
                request.app.session.commit()
                request.app.session.flush()

            except Exception as e:
                logging.getLogger().info("Exception saving authentication{}".format(e))
                request.app.session.rollback()
            return sanic_response_json({"Validation_status": "Not Matching"})

        auth_status_response = await make_authentication_status_secret(
            request, auth_request_id, validation['validation_data_secret']
            )
        authentication_status_secret = json.loads(auth_status_response.body.decode('utf-8')).\
            get("authentication_status_secret")

        try:
            authentication.authentication_result = AuthenticationResult.allowed.name
            authentication.authentication_status = AuthenticationStatus.completed.name
            authentication.authentication_status_secret = authentication_status_secret
            authentication.authentication_session_status = AuthenticationSessionStatus.active.name
            authentication.updated_at = datetime.utcnow()
            authentication.logged_in_at = datetime.utcnow()
            authentication.save()
            request.app.session.commit()
            request.app.session.flush()

        except Exception as e:
            logging.getLogger().info("Exception saving authentication{}".format(e))
            request.app.session.rollback()

        return sanic_response_json({
                                    "authentication_status": {
                                                    "authenticated": True,
                                                    "session_status": authentication.authentication_session_status,
                                                    "authentication_status_secret": authentication_status_secret,
                                                        }
                                                })


# ***********************************************
# Confirm Proximity Views
# ***********************************************

class ConfirmProximityView(HTTPMethodView):

    async def post(self, request, auth_request_id):

        # service_id, service_secret = get_service_credentials(request.app, "AUTHENTICATION_SERVICE")
        # verify_authentication_headers(request.app, request.headers, service_secret, request.url)

        try:
            authentication_verifying = request.app.session.query(Authentication). \
                filter(or_(Authentication.authentication_session_status == AuthenticationSessionStatus.verifying.name,
                           Authentication.authentication_session_status == AuthenticationSessionStatus.walkaway.name,

                           Authentication.authentication_session_status == AuthenticationSessionStatus.idle.name)). \
                filter(Authentication.auth_request_id == auth_request_id).\
                one()
        except Exception as e:
            logging.getLogger().info("Alchemy Exception: {}".format(e))
            request.app.session.rollback()

        try:
            if authentication_verifying:
                try:
                    try:
                        devices = json.loads(authentication_verifying.devices)
                    except Exception as e:
                        devices = None

                    authentication_verifying.authentication_session_status = AuthenticationSessionStatus.active.name
                    walkaway_data = dict()
                    walkaway_data['walkaway_count'] = 0
                    walkaway_data['walkaway_times'] = []
                    authentication_verifying.walkaway_data = json.dumps(walkaway_data)
                    authentication_verifying.updated_at = datetime.utcnow()
                    authentication_verifying.save()
                    request.app.session.commit()
                    logging.getLogger().info(
                        "Authentication with id={0} was set to active ".format(
                            authentication_verifying.id))

                    return sanic_response_json({
                        "status": "Success"
                    }, status=200)

                except Exception as e:
                    logging.getLogger().info("Alchemy Exception: {}".format(e))
                    request.app.session.rollback()

                    return sanic_response_json({
                        "status": "No Authentications Updated - Updates Failed"
                    }, status=200)
            else:
                logging.getLogger().info("Exception: {}".format(e))

                return sanic_response_json({
                    "status": "No Authentications to Update"
                }, status=200)

        except Exception as e:
            logging.getLogger().info("Exception: {}".format(e))

            return sanic_response_json({
                        "status": "No Authentications to Update"
                    }, status=200)

# ***********************************************
# Application Status Views
# ***********************************************

class ApplicationStatusView(HTTPMethodView):

    async def post(self, request):

        # service_id, service_secret = get_service_credentials(request.app, "AUTHENTICATION_SERVICE")
        # verify_authentication_headers(request.app, request.headers, service_secret, request.url)

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)
        logging.getLogger().info("Got the Following data in the request: {}".format(data))
        push_notification_token = data["push_notification_token"]
        status = data["status"]

        try:
            devices = request.app.session.query(Device). \
                filter(Device.push_notification_token == push_notification_token). \
                filter(Device.deleted_at == None). \
                all()
            logging.getLogger().info("Got the following devices:{}".format(devices))
            for device in devices:

                if (status):
                    authentications = request.app.session.query(Authentication). \
                        filter(Authentication.authentication_session_status == AuthenticationSessionStatus.idle.name). \
                        filter(Authentication.mobile_device.contains(device.device_id)).\
                        all()
                    logging.getLogger().info("Status is true; Got the following authentications: {}".format(authentications))
                else:
                    authentications = request.app.session.query(Authentication). \
                        filter(
                        or_(Authentication.authentication_session_status == AuthenticationSessionStatus.verifying.name,
                            Authentication.authentication_session_status == AuthenticationSessionStatus.active.name)). \
                        filter(Authentication.mobile_device.contains(device.device_id)). \
                        all()
                    logging.getLogger().info("Status is false; Got the following authentication: {}".format(authentications))
                if authentications:
                    try:
                        for authentication in authentications:
                            if (status):
                                authentication.authentication_session_status = AuthenticationSessionStatus.active.name
                                status_log = True
                            else:
                                authentication.authentication_session_status = AuthenticationSessionStatus.idle.name
                                status_log = False
                            authentication.updated_at = datetime.utcnow()
                            authentication.save()
                            request.app.session.commit()
                            if (status_log):

                                logging.getLogger().info(
                                    "Authentication with id={0} was set to active ".format(
                                        authentication.id))
                            else:
                                logging.getLogger().info(
                                    "Authenticationwith id={0} was set to idle ".format(
                                        authentication.id))

                    except Exception as e:
                        logging.getLogger().info("Alchemy Exception: {}".format(e))
                        request.app.session.rollback()

        except Exception as e:
            logging.getLogger().info("Alchemy Exception: {}".format(e))
            request.app.session.rollback()

            return sanic_response_json({
                "status": "No Authentications Updated - Updates Failed"
            }, status=200)

        return sanic_response_json({
            "status": "Success"
        }, status=200)


# ***********************************************
# Global View Methods
# ***********************************************

class IdentificationService():
    @staticmethod
    def kill_sessions(request, user_id):
        url = ''.join([
            request.app.hububconfig.get('IDENTIFICATION_PUSH_NOTIFICATION_BASE_URL'),
            '/api/v1/authentication/killsessions/{}'.format(user_id)
        ])
        logging.getLogger().info("Sending request to {} to kill sessions".format(url))
        service_id, service_secret = get_service_credentials(request.app, "IDENTIFICATION_PUSH_NOTIFICATION")
        headers = make_authentication_headers(service_id, service_secret, url)

        headers['Connection'] = "close"
        headers['Content-Type'] = "text/html"

        try:
            post_push_notification_reponse = requests.post(url, headers=headers, verify=False)

        except requests.HTTPError as exc:
            handle_response_on_error(exc.response, exc)

        return post_push_notification_reponse

    @staticmethod
    async def post_push_notification(request, user_id, auth_request_id, push_notification_certificate_id,
                                     requested_data=None, action=None, validation=None, communication=None):
        url = ''.join([
            request.app.hububconfig.get('IDENTIFICATION_PUSH_NOTIFICATION_BASE_URL'),
            '/api/v1/authentication/identification/push_notification_services'
        ])

        logging.getLogger().info("Sending request to {} to make push notification".format(url))

        service_id, service_secret = get_service_credentials(request.app, "IDENTIFICATION_PUSH_NOTIFICATION")
        headers = make_authentication_headers(service_id, service_secret, url)

        data = {
            'user_id': user_id,
            'auth_request_id': auth_request_id,
            'push_notification_certificate_id': push_notification_certificate_id
        }

        if requested_data:
            data['requested_data'] = requested_data
        if validation:
            data['validation'] = validation

        if communication:
            data['communication'] = communication

        if action:
            data["action"] = action
        identification_data_secret = generate_secret_key()

        identification_data = {
            "identification_data_secret": identification_data_secret,
            "user_id": user_id
        }

        if requested_data:
            identification_data.update({"requested_data": requested_data})

        if validation:
            identification_data.update({"validation": validation})
        identification_data.update({"os_authentication": {}})
        identification_data.update({"proximity": {}})
        logging.getLogger().info("Communication is  current = {}".format(communication))
        if communication:
            if communication['method']:
                if communication['method'] == 'audio_bluetooth':
                    token_length = request.app.hububconfig.get('BLUETOOTH_SERVICE_IDENTIFIER_LENGTH')
                    logging.getLogger().info("Commuication method is audio_bluetooth")
                    communication['bluetooth'] = {
                        'service_identifier': generate_secret_key(token_length * 8)[:token_length]
                    }
                elif communication['method'] == 'bluetooth':
                    token_length = request.app.hububconfig.get('BLUETOOTH_ONLY_SERVICE_IDENTIFIER_LENGTH')
                    logging.getLogger().info("Communication method is bluetooth")
                    communication['bluetooth'] = {
                        'service_identifier': generate_secret_key(token_length * 8)[:token_length]
                    }
                elif communication['method'] == 'validation_server':
                    token_length = request.app.hububconfig.get('VALIDATION_SERVER_TOKEN_LENGTH')
                    logging.getLogger().info("communication method is validation_server")
                    communication['validation_server'] = {
                        'token': generate_secret_key(token_length * 8)[:token_length]
                    }
        validation_json = json.loads(validation)
        identification_data.update({"communication": communication})
        data['communication'] = communication
        data['identification_data_secret'] = identification_data['identification_data_secret']
        data['user_id'] = identification_data['user_id']
        data['validation_data_secret'] = validation_json['validation_data_secret']
        data['validation_prefix'] = validation_json['validation_prefix']
        data['validation_secret'] = validation_json['validation_secret']
        logging.getLogger().info("Sending request to {} to make push notification with data - {}".format(url, data))
        status = await redisset(request.app, auth_request_id, json.dumps(data), RedisDatabase.Authentication)
        validation_status = await redisset(request.app, auth_request_id, data['validation_data_secret'], RedisDatabase.Session)
        headers['Content-Type'] = "text/html"
        request_data = json.dumps(data)
        logging.getLogger().info("Final request_data = {}".format(request_data))
        if status:

            try:
                post_push_notification_reponse = requests.post(url, data=request_data, headers=headers, verify=False)

            except requests.HTTPError as exc:
                handle_response_on_error(exc.response, exc)

            return post_push_notification_reponse

        else:
            return None

class ProximityDataView(HTTPMethodView):

    # @async_validate_strict_schema(AuthenticationStatusSchema())
    async def post(self, request, auth_request_id):

        encoding = request.body.decode("utf-8")
        data = json.loads(encoding)

        logging.getLogger().info(
            "Got POST request for proximity with auth_request_id={}".format(auth_request_id))

        logging.getLogger().info("payload = {}".format(data))

        # Find the authentication record form the auth request id.
        try:
            authentication = request.app.session.query(Authentication).filter(
                Authentication.auth_request_id == auth_request_id). \
                filter(Authentication.deleted_at == None).one_or_none()

            # Did we find the authentication record?
            if authentication is not None:

                if authentication.authentication_session_status == AuthenticationSessionStatus.expired.name or \
                   authentication.authentication_session_status == AuthenticationSessionStatus.closed.name:
                    logging.getLogger().info("Session with {} is expired oor closed".format(authentication.authentication_session_status))
                    return sanic_response_json({
                        "status": True, "action": "stop"
                    })

                base_power = authentication.walkaway_data

                using_default_power = False
                if base_power is None:
                    using_default_power = True
                    base_power = request.app.hububconfig.get('PROXIMITY_DEFAULT_POWER')
                else:
                    logging.getLogger().info("Login RSSI before conversion is {} type is".format(base_power, type(base_power)))
                    base_power = int(base_power)
                    logging.getLogger().info("Login RSSI after conversion is {} type is {}".format(base_power, type(base_power)))



                #logging.getLogger().info( "Base RSSI = {}".format(base_power))


                #power_delta = await rssi_range_for_user(request, authentication.user_id, True)
                power_delta = request.app.hububconfig.get('PROXIMITY_RSSI_RANGE')


                min_power = abs(base_power - power_delta)
                logging.getLogger().info(
                    "Login RSSI = {} power delta = {} min power = {} default {}".format(base_power, power_delta, min_power, using_default_power))
                # Get the rssi as an integer and check if it is high enough.
                try:
                    rssi = abs(int(data['rssi']))

                    if rssi <= min_power:
                        # The rssi is high enough so we update the last update time.
                        logging.getLogger().info("rssi is high enough {}".format(rssi))
                        authentication.updated_at = datetime.utcnow()

                        # If the app is in walkaway and we see the app again, we set the status to active.
                        if authentication.authentication_session_status == AuthenticationSessionStatus.walkaway.name:
                            authentication.authentication_session_status = AuthenticationSessionStatus.active.name

                        authentication.save()
                        request.app.session.commit()
                    else:
                        logging.getLogger().info("rssi too low {}".format(rssi))
                except (ValueError, KeyError, TypeError) as exc:
                    logging.getLogger().error("Invalid proximity data.")
                    return sanic_response_json({
                        "status": False, "action": "stop"
                    })

                return sanic_response_json({ "status": True, "action": "continue" })
            else:
                logging.getLogger().error(
                    "Could not get authentication with auth_request_id={}".format(auth_request_id))
                return sanic_response_json({"status": False, "action": "stop" })

        except SQLAlchemyError as e:
            request.app.session.rollback()
            logging.getLogger().error("Could not get authentication with auth_request_id={}".format(auth_request_id))
            return sanic_response_json({"status": False, "action": "stop"})

