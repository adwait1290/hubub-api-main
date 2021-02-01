
from .views import (
    ApiVersionView,
    AppleAppSiteAssociationView,
    AuthenticationLoginView,
    AuthenticationLogoutView,
    ValidateAuthStatus,
    AuthenticationPingView,
    RequestValidationView,
    DestroyAuthSession,
    AuthenticationStatusView,
    ConfirmProximityView,
    ApplicationStatusView,
    GetAuthStatus,
    ProximityDataView)


__all__ = (
    'setup_routes'
)


def setup_routes(blueprint):
    # Authentication Views
    blueprint.add_route(ApiVersionView.as_view(), '/version', methods=['GET', 'OPTIONS'])

    blueprint.add_route(AuthenticationLoginView.as_view(), '/accounts/users/<username>/login', methods=['POST', 'OPTIONS'])
    blueprint.add_route(AuthenticationLogoutView.as_view(), '/accounts/users/<username>/logout', methods=['GET', 'POST', 'OPTIONS'])
    blueprint.add_route(AuthenticationStatusView.as_view(), 'authentication/status/<auth_request_id>',
                        methods=['POST','GET','OPTIONS'])
    blueprint.add_route(ValidateAuthStatus.as_view(), '/authentication/validate_status/<auth_request_id>',
                        methods=['POST', 'OPTIONS'])
    blueprint.add_route(DestroyAuthSession.as_view(), '/authentication/destroy_session/<auth_request_id>',
                        methods=['POST', 'OPTIONS'])
    # Validation Views
    blueprint.add_route(RequestValidationView.as_view(), '/authentication/validations/<auth_request_id>',
                        methods=['POST', 'OPTIONS'])
    # Authentication Ping
    blueprint.add_route(AuthenticationPingView.as_view(), '/authentication/ping/<user_id>', methods=['POST', 'OPTIONS'])
    # Confirm Proximity
    blueprint.add_route(ConfirmProximityView.as_view(), '/confirm_proximity/<auth_request_id>', methods=['POST', 'OPTIONS'])
    # Application Status
    blueprint.add_route(ApplicationStatusView.as_view(), '/application_status', methods=['POST', 'OPTIONS'])
    blueprint.add_route(GetAuthStatus.as_view(), '/authentication/get_status/<auth_request_id>', methods=['POST', 'OPTIONS'])

    # Proximity View
    blueprint.add_route(ProximityDataView.as_view(), '/authentication/proximity/<auth_request_id>', methods=['POST', 'OPTIONS'])



def setup_routes2(blueprint):
    blueprint.add_route(AppleAppSiteAssociationView.as_view(), '/apple-app-site-association',
                        methods=['GET', 'POST', 'OPTIONS'])