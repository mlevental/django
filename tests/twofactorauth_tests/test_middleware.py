from tests.twofactorauth_tests.test_views import TFAViewsTestCase

from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.twofactorauth import DEVICE_ID_SESSION_KEY
from django.contrib.twofactorauth.middleware import TFAMiddleware
from django.http import HttpRequest


class TestTFAMiddleware(TFAViewsTestCase):
    def auth_middleware_process_request(self):
        self.request = HttpRequest()
        self.request.session = self.client.session
        AuthenticationMiddleware().process_request(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertFalse(self.request.user.is_anonymous)

    def test_two_factor_authenticated_user(self):
        """
        A TFA device is set for a two factor authenticated user.
        """
        self.two_factor_login()
        self.auth_middleware_process_request()

        TFAMiddleware().process_request(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertIsNotNone(self.request.user.tfa_device)

    def test_one_factor_authenticated_user(self):
        """
        No TFA device is set for a one factor authenticated user.
        """
        self.first_factor_login()
        self.auth_middleware_process_request()

        TFAMiddleware().process_request(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertIsNone(self.request.user.tfa_device)

    def test_device_doesnt_belong_to_user(self):
        """
        A TFA device is rejected if it doesn't belong to the user in the request.
        """
        self.first_factor_login()
        self.auth_middleware_process_request()
        self.request.session[DEVICE_ID_SESSION_KEY] = self.device2.persistent_id

        TFAMiddleware().process_request(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertIsNone(self.request.user.tfa_device)
        self.assertNotIn(DEVICE_ID_SESSION_KEY, self.request.session)
