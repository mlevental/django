from django.conf import settings
from django.contrib.auth.decorators import user_passes_test


def tfa_required(function=None, redirect_field_name='next', tfa_login_url=None):
    """
    Decorator for views that checks that the user is authenticated with
    two factors, redirecting to the TFA log-in page if necessary.
    """

    if tfa_login_url is None:
        tfa_login_url = settings.TFA_LOGIN_URL

    decorator = user_passes_test(
        lambda u: u.is_two_factor_authenticated,
        login_url=tfa_login_url,
        redirect_field_name=redirect_field_name
    )

    if function:
        return decorator(function)
    return decorator
