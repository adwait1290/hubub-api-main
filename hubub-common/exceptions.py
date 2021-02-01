import json
import logging
from sanic.exceptions import abort
from sanic.response import json as sanic_response_json
from sanic.views import HTTPMethodView

class BaseAuthenticationException(Exception):
    """
    Base class for all exceptions that are related to authentication process
    and describes its basic structure.
    Needs to be overwritten to handle specific exception type.
    """
    status_code = 500
    status = ""
    description = ""
    uri = "https://support.hubub.com/api/doc/v0.1/authentication.html"

    def __init__(self, status=None, description=None, status_code=None, uri=None):
        super(BaseAuthenticationException, self).__init__()
        if status is not None:
            self.status = status
        if description is not None:
            self.description = description
        if status_code is not None:
            self.status_code = status_code
        if uri is not None:
            self.uri = uri

    def to_dict(self):
        return {
            "error": {
                "status": self.status,
                "description": self.description,
                "uri": self.uri
            }
        }


class BaseHTTPException(Exception):
    status_code = 400

    def __init__(self, json_data, status=None, status_code=400, **kwargs):
        self.status_code = status_code
        if status is None:
            body = json_data
        else:
            body = {
                'error': {
                    'status': status,
                    'description': json_data
                }
            }
        kwargs['body'] = str.encode(json.dumps(body))
        kwargs['content_type'] = 'application/json'

        super().__init__(**kwargs)


class ExpiredCredentialsException(BaseAuthenticationException):
    status_code = 401
    status = "authentication_failed"
    description = "Credentials have expired"


class InvalidCredentialsException(BaseAuthenticationException):
    status_code = 401
    status = "invalid_credentials"
    description = "API client credentials are not valid"


class InvalidHeaderCredentialsException(HTTPMethodView):

    def raiseit(self):
        response = {
            "authentication_status": {
                "status_code": 401,
                "status": "invalid_credentials",
                "description": "API client credentials are not valid",
                "authenticated": False,
                "session_status": "Headers Authentication Failed"
            }
        }

        return sanic_response_json(response)


class InvalidValueException(BaseAuthenticationException):
    status_code = 400
    status = "value_invalid"
    description = "A parameter {parameter} has an invalid value for the request"

    def __init__(self, parameter=None, **kwargs):
        super(InvalidValueException, self).__init__(**kwargs)
        if parameter:
            self.description = self.description.format(parameter=parameter)


class InvalidParameterException(BaseAuthenticationException):
    status_code = 400
    status = "parameter_invalid"
    description = "The parameter {parameter} is not supported or understood"

    def __init__(self, parameter, **kwargs):
        super(InvalidParameterException, self).__init__(**kwargs)
        self.description = self.description.format(parameter=parameter)


class PermissionDenied(BaseAuthenticationException):
    status_code = 403
    status = "permission_denied"

    def __init__(self, **kwargs):
        policies = kwargs.pop("policies", [])
        if isinstance(policies, str):
            policies = [policies]
        self.policies = policies

        super(PermissionDenied, self).__init__(**kwargs)

    def to_dict(self):
        dict_data = super(PermissionDenied, self).to_dict()

        if self.policies:
            dict_data["error"]["policy"] = self.policies
        return dict_data


class ClientApiDisabled(BaseAuthenticationException):
    status_code = 403
    status = "client_api_disabled"
    description = "The API client has been disabled or it has expired"


class AccountDisabled(BaseAuthenticationException):
    status_code = 403
    status = "account_disabled"
    description = "The account has been disabled or it has expired"


class UserDisabled(BaseAuthenticationException):
    status_code = 403
    status = "user_disabled"
    description = "The user's account has been disabled or it has expired"


class IdentificationDeviceNotRegistered(BaseAuthenticationException):
    status_code = 500
    status = "identification_device_not_registered"
    description = "There is no identification device that is currently registered"


class PushNotificationNotConfigured(BaseAuthenticationException):
    status_code = 500
    status = "push_notification_not_configured"
    description = ("For the currently active identification device, there is no valid push "
                   "notification configuration")


class InvalidTokenException(BaseHTTPException):
    status_code = 401


class RecordNotFound(Exception):
    """Requested record in database was not found"""

def handle_response_on_error(app, response, exc=None):
    """ Handles situation when an error occurred during sending HTTP request."""
    try:
        error = response.json().get('error', response.json())
    except ValueError:
        error = response.text

    if exc is not None:
        logging.getLogger().warn("Got an exception : {}".format(exc))

        logging.getLogger().warn("Response content : {}".format(error))
    abort(response.status_code, error=error)